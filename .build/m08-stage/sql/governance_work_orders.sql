-- Additive persistence for WorkOrder ownership, execution dependencies, and attempts.
-- Apply only after sql/init.sql on the dedicated PADDOCK database.
-- Creates no database/schema and drops no existing object.

BEGIN;

DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing WorkOrder migration on %, expected paddock_test', current_database();
    END IF;
    IF NOT EXISTS (
        SELECT 1
          FROM pg_catalog.pg_class AS table_catalog
          JOIN pg_catalog.pg_namespace AS schema_catalog ON schema_catalog.oid = table_catalog.relnamespace
         WHERE schema_catalog.nspname = 'raw'
           AND table_catalog.relname = 'roots'
           AND table_catalog.relkind IN ('r', 'p')
    ) THEN
        RAISE EXCEPTION 'required base table raw.roots is missing';
    END IF;
END
$$;

CREATE TABLE raw.work_orders (
    work_order_id text PRIMARY KEY CHECK (work_order_id <> '' AND work_order_id = btrim(work_order_id)),
    root_id       text NOT NULL REFERENCES raw.roots(root_id),
    parent_id     text,
    created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (work_order_id, root_id),
    CHECK (parent_id IS NULL OR (parent_id <> '' AND parent_id = btrim(parent_id))),
    CHECK (parent_id IS NULL OR parent_id <> work_order_id),
    CONSTRAINT work_orders_parent_same_root_fk
        FOREIGN KEY (parent_id, root_id)
        REFERENCES raw.work_orders(work_order_id, root_id)
        DEFERRABLE INITIALLY DEFERRED
);

-- A Root may have at most one ownership-tree root node.
CREATE UNIQUE INDEX work_orders_one_tree_root_per_root_uidx
    ON raw.work_orders(root_id) WHERE parent_id IS NULL;

CREATE FUNCTION raw.reject_work_order_parent_cycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    creates_cycle boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'ownership cycle check requires READ COMMITTED isolation; retry transaction'
            USING ERRCODE = 'serialization_failure';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.root_id, 0));
    IF NEW.parent_id IS NULL THEN
        RETURN NEW;
    END IF;
    WITH RECURSIVE ancestors(work_order_id) AS (
        SELECT NEW.parent_id
        UNION
        SELECT parent.parent_id
          FROM raw.work_orders AS parent
          JOIN ancestors ON parent.work_order_id = ancestors.work_order_id
         WHERE parent.root_id = NEW.root_id
           AND parent.parent_id IS NOT NULL
    )
    SELECT EXISTS (
        SELECT 1 FROM ancestors WHERE work_order_id = NEW.work_order_id
    ) INTO creates_cycle;
    IF creates_cycle THEN
        RAISE EXCEPTION 'parent assignment for % creates an ownership cycle', NEW.work_order_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER work_orders_no_parent_cycle_trg
BEFORE INSERT ON raw.work_orders
FOR EACH ROW EXECUTE FUNCTION raw.reject_work_order_parent_cycle();
CREATE FUNCTION raw.reject_work_order_identity_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.work_order_id IS DISTINCT FROM OLD.work_order_id
       OR NEW.root_id IS DISTINCT FROM OLD.root_id
       OR NEW.parent_id IS DISTINCT FROM OLD.parent_id THEN
        RAISE EXCEPTION 'work order identity and ownership are immutable'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER work_orders_identity_immutable_trg
BEFORE UPDATE ON raw.work_orders
FOR EACH ROW EXECUTE FUNCTION raw.reject_work_order_identity_update();

CREATE TABLE raw.work_order_dependencies (
    root_id        text NOT NULL,
    work_order_id  text NOT NULL,
    depends_on_id  text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (work_order_id, depends_on_id),
    CHECK (work_order_id <> depends_on_id),
    CONSTRAINT work_order_dependencies_work_same_root_fk
        FOREIGN KEY (work_order_id, root_id)
        REFERENCES raw.work_orders(work_order_id, root_id),
    CONSTRAINT work_order_dependencies_dep_same_root_fk
        FOREIGN KEY (depends_on_id, root_id)
        REFERENCES raw.work_orders(work_order_id, root_id)
);
CREATE INDEX work_order_dependencies_root_dep_idx
    ON raw.work_order_dependencies(root_id, depends_on_id);

-- Serialize edge insertion per Root so concurrent writers cannot each observe
-- an acyclic partial graph and jointly commit a cycle. hash collisions only
-- cause extra serialization; they do not weaken correctness.
CREATE FUNCTION raw.reject_work_order_dependency_cycle()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
    creates_cycle boolean;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'dependency cycle check requires READ COMMITTED isolation; retry transaction'
            USING ERRCODE = 'serialization_failure';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.root_id, 0));
    WITH RECURSIVE reachable(work_order_id) AS (
        SELECT NEW.depends_on_id
        UNION
        SELECT edge.depends_on_id
          FROM raw.work_order_dependencies AS edge
          JOIN reachable ON edge.work_order_id = reachable.work_order_id
         WHERE edge.root_id = NEW.root_id
    )
    SELECT EXISTS (
        SELECT 1 FROM reachable WHERE work_order_id = NEW.work_order_id
    ) INTO creates_cycle;

    IF creates_cycle THEN
        RAISE EXCEPTION 'dependency edge % -> % creates a cycle', NEW.work_order_id, NEW.depends_on_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER work_order_dependencies_no_cycle_trg
BEFORE INSERT ON raw.work_order_dependencies
FOR EACH ROW EXECUTE FUNCTION raw.reject_work_order_dependency_cycle();

CREATE FUNCTION raw.reject_work_order_dependency_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'work order dependencies are immutable; insert a new graph revision'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER work_order_dependencies_immutable_trg
BEFORE UPDATE ON raw.work_order_dependencies
FOR EACH ROW EXECUTE FUNCTION raw.reject_work_order_dependency_update();

CREATE TABLE raw.work_order_attempts (
    attempt_id     text PRIMARY KEY CHECK (attempt_id <> '' AND attempt_id = btrim(attempt_id)),
    work_order_id  text NOT NULL REFERENCES raw.work_orders(work_order_id),
    attempt_number bigint NOT NULL CHECK (attempt_number > 0),
    created_at     timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (work_order_id, attempt_number)
);
CREATE INDEX work_order_attempts_order_idx
    ON raw.work_order_attempts(work_order_id, attempt_number);
CREATE FUNCTION raw.reject_work_order_attempt_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'work order attempts are immutable history'
        USING ERRCODE = 'check_violation';
END
$$;
CREATE TRIGGER work_order_attempts_immutable_trg
BEFORE UPDATE ON raw.work_order_attempts
FOR EACH ROW EXECUTE FUNCTION raw.reject_work_order_attempt_update();

COMMIT;

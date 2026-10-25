CREATE OR REPLACE FUNCTION raw.reject_work_order_parent_cycle()
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
CREATE OR REPLACE FUNCTION raw.reject_work_order_dependency_cycle()
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

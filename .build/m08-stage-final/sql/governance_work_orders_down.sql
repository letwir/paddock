-- Reverse only sql/governance_work_orders.sql on the dedicated PADDOCK DB.
-- No database, schema, root, or pre-existing governance table is dropped.
\set ON_ERROR_STOP on
BEGIN;
DO $$
BEGIN
    IF current_database() <> 'paddock_test' THEN
        RAISE EXCEPTION 'refusing WorkOrder rollback on %, expected paddock_test', current_database();
    END IF;
END
$$;
DROP TABLE raw.work_order_attempts;
DROP FUNCTION raw.reject_work_order_attempt_update();
DROP TRIGGER work_order_dependencies_no_cycle_trg ON raw.work_order_dependencies;
DROP TRIGGER work_order_dependencies_immutable_trg ON raw.work_order_dependencies;
DROP FUNCTION raw.reject_work_order_dependency_cycle();
DROP FUNCTION raw.reject_work_order_dependency_update();
DROP TABLE raw.work_order_dependencies;
DROP TRIGGER work_orders_no_parent_cycle_trg ON raw.work_orders;
DROP TRIGGER work_orders_identity_immutable_trg ON raw.work_orders;
DROP FUNCTION raw.reject_work_order_parent_cycle();
DROP FUNCTION raw.reject_work_order_identity_update();
DROP TABLE raw.work_orders;
COMMIT;

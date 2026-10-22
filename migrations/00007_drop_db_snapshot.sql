-- +goose Up
-- Database scans keep only findings and counts; the inspected structure is
-- not stored (data minimisation).
ALTER TABLE db_scans DROP COLUMN snapshot_gz;

-- +goose Down
ALTER TABLE db_scans ADD COLUMN snapshot_gz bytea;

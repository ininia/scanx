-- +goose Up
-- Repository scan scope and forecast: projects.settings holds what scans
-- cover (excluded paths, file groups, switched-off scanners); scan_stats
-- what the worker learned from the latest scan (analysis tree size, the
-- estimate and the actual duration) for the next forecast.
ALTER TABLE projects ADD COLUMN scan_stats jsonb NOT NULL DEFAULT '{}'::jsonb;

-- +goose Down
ALTER TABLE projects DROP COLUMN scan_stats;

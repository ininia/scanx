-- +goose Up
-- Incremental (diff) scans: a push scans only the files it changed.
ALTER TABLE projects ADD COLUMN push_scope text NOT NULL DEFAULT 'diff'
    CHECK (push_scope IN ('diff', 'full'));
ALTER TABLE scans ADD COLUMN scope text NOT NULL DEFAULT 'full'
    CHECK (scope IN ('full', 'diff'));
ALTER TABLE scans ADD COLUMN base_sha text NOT NULL DEFAULT '';
ALTER TABLE scans ADD COLUMN changed_files int;

-- +goose Down
ALTER TABLE scans DROP COLUMN changed_files;
ALTER TABLE scans DROP COLUMN base_sha;
ALTER TABLE scans DROP COLUMN scope;
ALTER TABLE projects DROP COLUMN push_scope;

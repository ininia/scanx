-- +goose Up
-- Per-project time limit for the SAST step (opengrep) and a live progress
-- log shown on the scan page.
ALTER TABLE projects ADD COLUMN sast_timeout_minutes int NOT NULL DEFAULT 20
    CHECK (sast_timeout_minutes BETWEEN 5 AND 240);
ALTER TABLE scans ADD COLUMN log text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE scans DROP COLUMN log;
ALTER TABLE projects DROP COLUMN sast_timeout_minutes;

CREATE TABLE IF NOT EXISTS projects (id text PRIMARY KEY, state jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS updates (project text NOT NULL REFERENCES projects(id), sequence bigint NOT NULL, id text NOT NULL, author_id text NOT NULL, at bigint NOT NULL, document jsonb NOT NULL, PRIMARY KEY(project,sequence), UNIQUE(project,id));

-- Correção segura para defaults de produção no PostgreSQL.
-- Use preferencialmente as migrations: python -m flask db upgrade
-- Este SQL é um plano B para aplicar manualmente no banco, sem apagar dados.

BEGIN;

UPDATE users
SET role = 'user'
WHERE role IS NULL OR TRIM(role) = '';

UPDATE users
SET is_active = TRUE
WHERE is_active IS NULL;

UPDATE users
SET is_admin = FALSE
WHERE is_admin IS NULL;

UPDATE users
SET is_verified = FALSE
WHERE is_verified IS NULL;

UPDATE users
SET default_avatar = 'vazio'
WHERE default_avatar IS NULL OR TRIM(default_avatar) = '';

UPDATE users
SET default_visibility_mode = 'anonymous'
WHERE default_visibility_mode IS NULL
   OR default_visibility_mode NOT IN ('anonymous', 'profile');

UPDATE users
SET created_at = CURRENT_TIMESTAMP
WHERE created_at IS NULL;

UPDATE users
SET updated_at = COALESCE(updated_at, created_at, CURRENT_TIMESTAMP)
WHERE updated_at IS NULL;

ALTER TABLE users ALTER COLUMN role SET DEFAULT 'user';
ALTER TABLE users ALTER COLUMN role SET NOT NULL;
ALTER TABLE users ALTER COLUMN is_active SET DEFAULT TRUE;
ALTER TABLE users ALTER COLUMN is_active SET NOT NULL;
ALTER TABLE users ALTER COLUMN is_admin SET DEFAULT FALSE;
ALTER TABLE users ALTER COLUMN is_admin SET NOT NULL;
ALTER TABLE users ALTER COLUMN is_verified SET DEFAULT FALSE;
ALTER TABLE users ALTER COLUMN is_verified SET NOT NULL;
ALTER TABLE users ALTER COLUMN default_avatar SET DEFAULT 'vazio';
ALTER TABLE users ALTER COLUMN default_avatar SET NOT NULL;
ALTER TABLE users ALTER COLUMN default_visibility_mode SET DEFAULT 'anonymous';
ALTER TABLE users ALTER COLUMN default_visibility_mode SET NOT NULL;
ALTER TABLE users ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ALTER COLUMN created_at SET NOT NULL;
ALTER TABLE users ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ALTER COLUMN updated_at SET NOT NULL;

UPDATE posts
SET visivel = 1
WHERE visivel IS NULL;

UPDATE posts
SET status = 'published'
WHERE status IS NULL OR status NOT IN ('draft', 'published');

UPDATE posts
SET visibility_mode = 'anonymous'
WHERE visibility_mode IS NULL
   OR visibility_mode NOT IN ('anonymous', 'profile', 'alias');

UPDATE posts
SET emotional_tag = 'vazio'
WHERE emotional_tag IS NULL OR TRIM(emotional_tag) = '';

UPDATE posts
SET sensitive_flag = 0
WHERE sensitive_flag IS NULL;

UPDATE posts
SET mood_type = COALESCE(NULLIF(TRIM(mood_type), ''), emotional_tag, 'vazio')
WHERE mood_type IS NULL OR TRIM(mood_type) = '';

UPDATE posts
SET updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP)
WHERE updated_at IS NULL;

UPDATE posts
SET is_deleted = 0
WHERE is_deleted IS NULL;

UPDATE posts
SET report_count = 0
WHERE report_count IS NULL;

ALTER TABLE posts ALTER COLUMN visivel SET DEFAULT 1;
ALTER TABLE posts ALTER COLUMN visivel SET NOT NULL;
ALTER TABLE posts ALTER COLUMN status SET DEFAULT 'published';
ALTER TABLE posts ALTER COLUMN status SET NOT NULL;
ALTER TABLE posts ALTER COLUMN visibility_mode SET DEFAULT 'anonymous';
ALTER TABLE posts ALTER COLUMN visibility_mode SET NOT NULL;
ALTER TABLE posts ALTER COLUMN emotional_tag SET DEFAULT 'vazio';
ALTER TABLE posts ALTER COLUMN emotional_tag SET NOT NULL;
ALTER TABLE posts ALTER COLUMN sensitive_flag SET DEFAULT 0;
ALTER TABLE posts ALTER COLUMN sensitive_flag SET NOT NULL;
ALTER TABLE posts ALTER COLUMN mood_type SET DEFAULT 'vazio';
ALTER TABLE posts ALTER COLUMN mood_type SET NOT NULL;
ALTER TABLE posts ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE posts ALTER COLUMN updated_at SET NOT NULL;
ALTER TABLE posts ALTER COLUMN is_deleted SET DEFAULT 0;
ALTER TABLE posts ALTER COLUMN is_deleted SET NOT NULL;
ALTER TABLE posts ALTER COLUMN report_count SET DEFAULT 0;
ALTER TABLE posts ALTER COLUMN report_count SET NOT NULL;

COMMIT;

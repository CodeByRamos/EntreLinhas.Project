ALTER TABLE users ADD COLUMN profile_photo TEXT;
ALTER TABLE users ADD COLUMN default_avatar TEXT DEFAULT 'vazio';

ALTER TABLE posts ADD COLUMN emotional_tag TEXT DEFAULT 'vazio';
ALTER TABLE posts ADD COLUMN sensitive_flag INTEGER DEFAULT 0;
ALTER TABLE posts ADD COLUMN mood_type TEXT DEFAULT 'vazio';
ALTER TABLE posts ADD COLUMN updated_at TIMESTAMP;
ALTER TABLE posts ADD COLUMN is_deleted INTEGER DEFAULT 0;
ALTER TABLE posts ADD COLUMN report_count INTEGER DEFAULT 0;

ALTER TABLE reports ADD COLUMN reason TEXT DEFAULT 'outro';
ALTER TABLE reports ADD COLUMN details TEXT;
ALTER TABLE reports ADD COLUMN status TEXT DEFAULT 'pending';
ALTER TABLE reports ADD COLUMN created_at TIMESTAMP;

CREATE TABLE IF NOT EXISTS echoes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, post_id)
);

CREATE TABLE IF NOT EXISTS psychologists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    professional_title TEXT,
    crp TEXT,
    contact_email TEXT,
    contact_link TEXT,
    bio TEXT,
    is_verified INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS daily_texts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    author_name TEXT,
    date TEXT UNIQUE,
    mood TEXT,
    is_active INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

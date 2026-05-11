"""Schema SQLAlchemy planejado para migracao organizada do EntreLinhas.

O app atual ainda usa o repositorio SQLite em database.py para preservar o que ja
funciona. Estas classes documentam o alvo PostgreSQL/Flask-Migrate sem forcar uma
troca brusca de persistencia.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    nickname = db.Column(db.String(30), nullable=False)
    display_name = db.Column(db.String(30))
    bio = db.Column(db.String(240))
    profile_photo = db.Column(db.Text)
    default_avatar = db.Column(db.String(30), default="vazio")
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    content = db.Column("mensagem", db.Text, nullable=False)
    subject = db.Column("categoria", db.String(40), nullable=False)
    emotional_tag = db.Column(db.String(30), nullable=False, default="vazio")
    sensitive_flag = db.Column(db.Boolean, default=False, nullable=False)
    mood_type = db.Column(db.String(30), default="vazio")
    report_count = db.Column(db.Integer, default=0, nullable=False)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column("data_postagem", db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Like(db.Model):
    __tablename__ = "likes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "post_id", name="uq_like_user_post"),)


class Echo(db.Model):
    __tablename__ = "echoes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    __table_args__ = (db.UniqueConstraint("user_id", "post_id", name="uq_echo_user_post"),)


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    reason = db.Column(db.String(40), nullable=False, default="outro")
    details = db.Column(db.String(500))
    status = db.Column(db.String(30), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Psychologist(db.Model):
    __tablename__ = "psychologists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    professional_title = db.Column(db.String(120))
    crp = db.Column(db.String(40))
    contact_email = db.Column(db.String(254))
    contact_link = db.Column(db.Text)
    bio = db.Column(db.Text)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class DailyText(db.Model):
    __tablename__ = "daily_texts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(120))
    date = db.Column(db.Date, unique=True)
    mood = db.Column(db.String(30))
    is_active = db.Column(db.Boolean, default=True, nullable=False)

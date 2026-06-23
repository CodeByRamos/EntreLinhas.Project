"""SQLAlchemy schema usado por Flask-Migrate/Alembic.

As rotas legadas ainda acessam `database.py`, mas este schema é a fonte para
migrations em PostgreSQL e para a evolução gradual do repositório de dados.
"""

from datetime import datetime
import sqlalchemy as sa
from extensions import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)
    nickname = db.Column(db.String(30), nullable=False)
    display_name = db.Column(db.String(30))
    bio = db.Column(db.String(240))
    email = db.Column(db.String(254), unique=True)
    role = db.Column(db.String(30), nullable=False, default="user", server_default="user")
    avatar_url = db.Column(db.Text)
    profile_photo = db.Column(db.Text)
    default_avatar = db.Column(db.String(30), nullable=False, default="vazio", server_default="vazio")
    default_visibility_mode = db.Column(db.String(20), nullable=False, default="anonymous", server_default="anonymous")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, server_default=sa.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, server_default=sa.func.now(), onupdate=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Integer, default=1, server_default="1", nullable=False)
    is_admin = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    is_verified = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    email_verified_at = db.Column(db.DateTime)


class Profile(db.Model):
    __tablename__ = "profiles"

    id = db.Column(db.Integer, primary_key=True)
    nickname = db.Column(db.String(80), nullable=False)
    bio = db.Column(db.Text)
    token = db.Column(db.String(160), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Post(db.Model):
    __tablename__ = "posts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120))
    mensagem = db.Column(db.Text, nullable=False)
    data_postagem = db.Column(db.String(20), nullable=False)
    categoria = db.Column(db.String(40), nullable=False)
    visivel = db.Column(db.Integer, default=1, server_default="1", nullable=False)
    status = db.Column(db.String(20), nullable=False, default="published", server_default="published")
    alias_name = db.Column(db.String(80))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"))
    visibility_mode = db.Column(db.String(20), nullable=False, default="anonymous", server_default="anonymous")
    emotional_tag = db.Column(db.String(30), nullable=False, default="vazio", server_default="vazio")
    sensitive_flag = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    mood_type = db.Column(db.String(30), nullable=False, default="vazio", server_default="vazio")
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, server_default=sa.func.now(), onupdate=datetime.utcnow, nullable=False)
    is_deleted = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    report_count = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    # Marco de Superação: quando o autor marca o desabafo como "eu superei isso"
    overcome_at = db.Column(db.String(20))
    # Mensagem deixada para quem passa pela mesma situação (junto da superação)
    overcome_message = db.Column(db.Text)
    # Modo "Quero apenas ser ouvido": bloqueia comentários quando 1
    listen_only = db.Column(db.Integer, default=0, server_default="0", nullable=False)


class Comment(db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    mensagem = db.Column(db.String(500), nullable=False)
    data_comentario = db.Column(db.String(20), nullable=False)
    visivel = db.Column(db.Integer, default=1, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"))


class Reaction(db.Model):
    __tablename__ = "reactions"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    reaction_type = db.Column(db.String(40), nullable=False)
    user_id = db.Column(db.String(80))
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"))
    data_reacao = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class ReactionCount(db.Model):
    __tablename__ = "reaction_counts"

    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), primary_key=True)
    reaction_type = db.Column(db.String(40), primary_key=True)
    count = db.Column(db.Integer, default=0, nullable=False)


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
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    data = db.Column(db.String(20))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"))
    reason = db.Column(db.String(40), nullable=False, default="outro")
    details = db.Column(db.String(500))
    status = db.Column(db.String(30), nullable=False, default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class CommentReport(db.Model):
    __tablename__ = "reports_comments"

    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comments.id"), nullable=False)
    user_id = db.Column(db.Integer, nullable=True)
    reason = db.Column(db.String(120), nullable=False)
    data_report = db.Column(db.String(20), nullable=False)
    resolved = db.Column(db.Integer, default=0, nullable=False)


class CommentKarma(db.Model):
    __tablename__ = "comment_karma"

    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comments.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    profile_id = db.Column(db.Integer, db.ForeignKey("profiles.id"))
    karma_type = db.Column(db.String(10), nullable=False)
    data = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(160), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class EmailVerificationToken(db.Model):
    __tablename__ = "email_verification_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(160), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Notification(db.Model):
    __tablename__ = "notifications"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    reference_id = db.Column(db.Integer)
    is_read = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SensitivePostLog(db.Model):
    __tablename__ = "sensitive_post_logs"

    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    risk_level = db.Column(db.String(20), nullable=False)


class Psychologist(db.Model):
    __tablename__ = "psychologists"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    professional_title = db.Column(db.String(120))
    crp = db.Column(db.String(40))
    contact_email = db.Column(db.String(254))
    contact_link = db.Column(db.Text)
    bio = db.Column(db.Text)
    estado = db.Column(db.String(2))
    cidade = db.Column(db.String(80))
    especialidades = db.Column(db.Text)
    modalidade = db.Column(db.String(20), default="ambos", server_default="ambos", nullable=False)
    photo_url = db.Column(db.Text)
    status = db.Column(db.String(20), default="pending", server_default="pending", nullable=False)
    is_verified = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    is_active = db.Column(db.Integer, default=1, server_default="1", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, server_default=sa.func.now(), nullable=False)
    # Snapshot da última revisão (auditoria detalhada vai em psychologist_reviews)
    reviewed_by_id = db.Column(db.Integer)
    reviewed_by_username = db.Column(db.String(80))
    reviewed_at = db.Column(db.String(20))
    review_notes = db.Column(db.Text)


class PsychologistReview(db.Model):
    """Trilha de auditoria das decisões sobre cadastros de psicólogos."""
    __tablename__ = "psychologist_reviews"

    id = db.Column(db.Integer, primary_key=True)
    psychologist_id = db.Column(db.Integer, db.ForeignKey("psychologists.id"), nullable=False)
    action = db.Column(db.String(30), nullable=False)          # approved/rejected/changes_requested
    status_to = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text)
    reviewer_id = db.Column(db.Integer)
    reviewer_username = db.Column(db.String(80))
    created_at = db.Column(db.String(20), nullable=False)


class ModerationAction(db.Model):
    """Histórico de ações de moderação sobre desabafos e respostas."""
    __tablename__ = "moderation_actions"

    id = db.Column(db.Integer, primary_key=True)
    target_type = db.Column(db.String(20), nullable=False)     # post/comment
    target_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(20), nullable=False)          # approve/hide/remove/review
    notes = db.Column(db.Text)
    moderator_id = db.Column(db.Integer)
    moderator_username = db.Column(db.String(80))
    created_at = db.Column(db.String(20), nullable=False)


class StrangerLetter(db.Model):
    """Carta anônima para desconhecidos. parent_id != NULL = resposta a outra carta."""
    __tablename__ = "stranger_letters"

    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    parent_id = db.Column(db.Integer)            # carta original, se for resposta
    is_hidden = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    report_count = db.Column(db.Integer, default=0, server_default="0", nullable=False)
    created_at = db.Column(db.String(20), nullable=False)


class StrangerLetterDelivery(db.Model):
    """Quem recebeu qual carta (evita reentrega e registra a ação tomada)."""
    __tablename__ = "stranger_letter_deliveries"

    id = db.Column(db.Integer, primary_key=True)
    letter_id = db.Column(db.Integer, db.ForeignKey("stranger_letters.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    action = db.Column(db.String(20))            # NULL / read / responded / forwarded
    created_at = db.Column(db.String(20), nullable=False)
    __table_args__ = (db.UniqueConstraint("letter_id", "recipient_id", name="uq_letter_recipient"),)


class FutureLetter(db.Model):
    __tablename__ = "future_letters"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    title = db.Column(db.String(120))
    content = db.Column(db.Text, nullable=False)
    open_at = db.Column(db.DateTime, nullable=False)
    opened_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default="SEALED", server_default="SEALED", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, server_default=sa.func.now(), nullable=False)


class DailyText(db.Model):
    __tablename__ = "daily_texts"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_name = db.Column(db.String(120))
    date = db.Column(db.Date, unique=True)
    mood = db.Column(db.String(30))
    is_active = db.Column(db.Integer, default=1, server_default="1", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


db.Index("idx_posts_emotional_tag", Post.emotional_tag)
db.Index("idx_posts_sensitive_flag", Post.sensitive_flag)
db.Index("idx_posts_report_count", Post.report_count)
db.Index("idx_reports_status", Report.status)
db.Index("idx_echoes_post_id", Echo.post_id)

"""Validacao e gravacao segura de uploads usados pelo perfil."""

import os
import secrets
from werkzeug.utils import secure_filename

ALLOWED_PROFILE_PHOTO_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_PROFILE_PHOTO_BYTES = 2 * 1024 * 1024
PROFILE_PHOTO_FOLDER = os.path.join("static", "uploads", "profile_photos")

_SIGNATURES = {
    "jpg": (b"\xff\xd8\xff",),
    "jpeg": (b"\xff\xd8\xff",),
    "png": (b"\x89PNG\r\n\x1a\n",),
    "webp": (b"RIFF",),
}


def _extension(filename):
    if "." not in (filename or ""):
        return ""
    return filename.rsplit(".", 1)[1].lower()


def _looks_like_allowed_image(file_storage, extension):
    position = file_storage.stream.tell()
    header = file_storage.stream.read(16)
    file_storage.stream.seek(position)
    if extension == "webp":
        return header.startswith(b"RIFF") and b"WEBP" in header[:16]
    return any(header.startswith(signature) for signature in _SIGNATURES.get(extension, ()))


def _file_size(file_storage):
    position = file_storage.stream.tell()
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(position)
    return size


def save_profile_photo(file_storage, user_id, project_root, old_path=None):
    if not file_storage or not file_storage.filename:
        return True, None

    original_name = secure_filename(file_storage.filename)
    extension = _extension(original_name)
    if extension not in ALLOWED_PROFILE_PHOTO_EXTENSIONS:
        return False, "Essa imagem nao parece estar em um formato valido."

    if _file_size(file_storage) > MAX_PROFILE_PHOTO_BYTES:
        return False, "Essa imagem esta um pouco pesada demais. Escolha uma foto de ate 2MB."

    if not _looks_like_allowed_image(file_storage, extension):
        return False, "Essa imagem nao parece estar em um formato valido."

    upload_dir = os.path.join(project_root, PROFILE_PHOTO_FOLDER)
    os.makedirs(upload_dir, exist_ok=True)

    filename = f"user-{user_id}-{secrets.token_hex(8)}.{extension}"
    file_storage.stream.seek(0)
    file_storage.save(os.path.join(upload_dir, filename))

    if old_path and old_path.startswith("/static/uploads/profile_photos/"):
        old_file = os.path.join(project_root, old_path.lstrip("/").replace("/", os.sep))
        new_file = os.path.join(upload_dir, filename)
        if os.path.abspath(old_file) != os.path.abspath(new_file) and os.path.exists(old_file):
            try:
                os.remove(old_file)
            except OSError:
                pass

    return True, f"/static/uploads/profile_photos/{filename}"

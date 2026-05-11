"""Camada de storage para uploads do EntreLinhas."""

import os
import secrets
from werkzeug.utils import secure_filename

ALLOWED_PROFILE_PHOTO_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
MAX_PROFILE_PHOTO_BYTES = int(os.environ.get("PROFILE_PHOTO_MAX_BYTES", str(2 * 1024 * 1024)))
PROFILE_PHOTO_SUBFOLDER = "profile_photos"

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


def _validate_profile_photo(file_storage):
    if not file_storage or not file_storage.filename:
        return True, None, None

    original_name = secure_filename(file_storage.filename)
    extension = _extension(original_name)
    if extension not in ALLOWED_PROFILE_PHOTO_EXTENSIONS:
        return False, "Essa imagem não parece estar em um formato válido.", None

    if _file_size(file_storage) > MAX_PROFILE_PHOTO_BYTES:
        return False, "Essa imagem está um pouco pesada demais. Escolha uma foto de até 2MB.", None

    if not _looks_like_allowed_image(file_storage, extension):
        return False, "Essa imagem não parece estar em um formato válido.", None

    return True, None, extension


def _public_local_url(upload_folder, filename):
    normalized = upload_folder.replace("\\", "/").strip("/")
    if normalized.startswith("static/"):
        return f"/{normalized}/{PROFILE_PHOTO_SUBFOLDER}/{filename}"
    return f"/static/uploads/{PROFILE_PHOTO_SUBFOLDER}/{filename}"


def _save_local(file_storage, user_id, project_root, extension, old_path=None):
    upload_folder = os.environ.get("UPLOAD_FOLDER", os.path.join("static", "uploads"))
    upload_dir = os.path.join(project_root, upload_folder, PROFILE_PHOTO_SUBFOLDER)
    os.makedirs(upload_dir, exist_ok=True)

    filename = f"user-{user_id}-{secrets.token_hex(12)}.{extension}"
    destination = os.path.abspath(os.path.join(upload_dir, filename))
    allowed_root = os.path.abspath(upload_dir)
    if not destination.startswith(allowed_root + os.sep):
        return False, "Não conseguimos salvar essa imagem agora."

    file_storage.stream.seek(0)
    file_storage.save(destination)

    if old_path and old_path.startswith("/static/uploads/profile_photos/"):
        old_file = os.path.abspath(os.path.join(project_root, old_path.lstrip("/").replace("/", os.sep)))
        if old_file.startswith(allowed_root + os.sep) and old_file != destination and os.path.exists(old_file):
            try:
                os.remove(old_file)
            except OSError:
                pass

    return True, _public_local_url(upload_folder, filename)


def _save_cloudinary(file_storage, user_id, extension):
    try:
        import cloudinary
        import cloudinary.uploader
    except ImportError:
        return False, "O storage externo ainda não está configurado neste ambiente."

    cloudinary.config(
        cloud_name=os.environ.get("CLOUDINARY_CLOUD_NAME"),
        api_key=os.environ.get("CLOUDINARY_API_KEY"),
        api_secret=os.environ.get("CLOUDINARY_API_SECRET"),
        secure=True,
    )
    if not all([os.environ.get("CLOUDINARY_CLOUD_NAME"), os.environ.get("CLOUDINARY_API_KEY"), os.environ.get("CLOUDINARY_API_SECRET")]):
        return False, "O storage externo ainda não está configurado neste ambiente."

    public_id = f"entrelinhas/profile_photos/user-{user_id}-{secrets.token_hex(12)}"
    file_storage.stream.seek(0)
    result = cloudinary.uploader.upload(
        file_storage.stream,
        public_id=public_id,
        folder=None,
        resource_type="image",
        format=extension,
        overwrite=False,
    )
    secure_url = result.get("secure_url")
    if not secure_url:
        return False, "Não conseguimos salvar essa imagem agora."
    return True, secure_url


def _save_s3(file_storage, user_id, extension):
    try:
        import boto3
    except ImportError:
        return False, "O storage externo ainda não está configurado neste ambiente."

    bucket = os.environ.get("AWS_S3_BUCKET")
    region = os.environ.get("AWS_REGION", "us-east-1")
    if not bucket:
        return False, "O storage externo ainda não está configurado neste ambiente."

    key = f"profile_photos/user-{user_id}-{secrets.token_hex(12)}.{extension}"
    content_type = {
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "webp": "image/webp",
    }[extension]

    client = boto3.client("s3", region_name=region)
    file_storage.stream.seek(0)
    client.upload_fileobj(
        file_storage.stream,
        bucket,
        key,
        ExtraArgs={"ContentType": content_type},
    )

    public_base = os.environ.get("AWS_PUBLIC_BASE_URL")
    if public_base:
        return True, f"{public_base.rstrip('/')}/{key}"
    return True, f"https://{bucket}.s3.{region}.amazonaws.com/{key}"


def save_profile_photo(file_storage, user_id, project_root, old_path=None):
    valid, message, extension = _validate_profile_photo(file_storage)
    if not valid:
        return False, message
    if extension is None:
        return True, None

    provider = os.environ.get("STORAGE_PROVIDER", "local").strip().lower()
    if provider == "cloudinary":
        return _save_cloudinary(file_storage, user_id, extension)
    if provider == "s3":
        return _save_s3(file_storage, user_id, extension)
    return _save_local(file_storage, user_id, project_root, extension, old_path=old_path)

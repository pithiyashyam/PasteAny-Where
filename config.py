import os


class Config:
    # In production, set this via an environment variable — never hardcode it.
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-only-change-this-secret-key')

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'storage', 'uploads')
    DATABASE = os.path.join(BASE_DIR, 'file_share.db')

    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload size

    ALLOWED_EXTENSIONS = {
        'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx',
        'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'csv', 'json', 'mp4', 'mp3', 'log'
    }

    TOKEN_EXPIRY_HOURS_DEFAULT = 24   # link validity
    MAX_DOWNLOADS_DEFAULT = 5         # 0 = unlimited

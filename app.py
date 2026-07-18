"""
Secure File Sharing API (Flask)
================================
Upload a file -> it is encrypted at rest and a secure, expiring, single-use-limited
download token is generated. Anyone with the token/link can retrieve the original
file (decrypted on the fly) until it expires, is revoked, or hits its download limit.

Intended to be exercised through Postman: upload from one Postman request,
copy the returned token/link, download it from another Postman request.

Run:
    python app.py
Then use the endpoints documented in README.md.
"""

import io
import os
import secrets
import sqlite3
import mimetypes
from datetime import datetime, timedelta

from flask import Flask, request, jsonify, send_file, g
from werkzeug.utils import secure_filename

from config import Config
import crypto_utils

app = Flask(__name__)
app.config.from_object(Config)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# NOTE: In production this salt should be a securely generated random value
# stored outside source control (e.g. env var), not a fixed literal.
_MASTER_SALT = b'file-share-master-salt-v1'
MASTER_KEY = crypto_utils.derive_master_key(app.config['SECRET_KEY'], _MASTER_SALT)


# --------------------------------------------------------------------------
# Database helpers (SQLite, one row per shared file)
# --------------------------------------------------------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                mime_type TEXT,
                uploaded_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                max_downloads INTEGER DEFAULT 5,
                download_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            )
        ''')
        db.commit()


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def generate_secure_token() -> str:
    """Cryptographically strong, URL-safe, unguessable token (256 bits of entropy)."""
    return secrets.token_urlsafe(32)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'service': 'flask-file-share'})


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """
    Postman setup:
      Method: POST
      URL:    http://127.0.0.1:5000/api/upload
      Body -> form-data:
        key = file        (type: File)  -> choose the file to upload
        key = expiry_hours (type: Text, optional, default 24)
        key = max_downloads (type: Text, optional, default 5, 0 = unlimited)
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request. Use form-data key "file".'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not allowed_file(file.filename):
        return jsonify({
            'error': 'File type not allowed',
            'allowed_extensions': sorted(app.config['ALLOWED_EXTENSIONS'])
        }), 400

    data = file.read()
    if len(data) == 0:
        return jsonify({'error': 'Uploaded file is empty'}), 400

    original_filename = secure_filename(file.filename)
    mime_type = file.mimetype or mimetypes.guess_type(original_filename)[0]

    try:
        expiry_hours = int(request.form.get('expiry_hours', app.config['TOKEN_EXPIRY_HOURS_DEFAULT']))
        max_downloads = int(request.form.get('max_downloads', app.config['MAX_DOWNLOADS_DEFAULT']))
    except ValueError:
        return jsonify({'error': 'expiry_hours and max_downloads must be integers'}), 400

    # --- Encrypt ---
    file_key = crypto_utils.generate_file_key()
    encrypted_data = crypto_utils.encrypt_bytes(data, file_key)
    encrypted_file_key = crypto_utils.encrypt_bytes(file_key, MASTER_KEY).decode()

    token = generate_secure_token()
    stored_filename = f'{token}.enc'
    stored_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    with open(stored_path, 'wb') as f:
        f.write(encrypted_data)

    uploaded_at = datetime.utcnow()
    expires_at = uploaded_at + timedelta(hours=expiry_hours)

    db = get_db()
    db.execute('''
        INSERT INTO files (token, original_filename, stored_filename, encrypted_key,
                            file_size, mime_type, uploaded_at, expires_at,
                            max_downloads, download_count, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 1)
    ''', (token, original_filename, stored_filename, encrypted_file_key,
          len(data), mime_type, uploaded_at.isoformat(), expires_at.isoformat(), max_downloads))
    db.commit()

    download_url = request.host_url.rstrip('/') + f'/api/download/{token}'

    return jsonify({
        'message': 'File uploaded and encrypted successfully',
        'token': token,
        'download_url': download_url,
        'original_filename': original_filename,
        'file_size_bytes': len(data),
        'expires_at': expires_at.isoformat() + 'Z',
        'max_downloads': max_downloads
    }), 201


@app.route('/api/download/<token>', methods=['GET'])
def download_file(token):
    """
    Postman setup:
      Method: GET
      URL:    http://127.0.0.1:5000/api/download/<token>
      (paste the token returned by /api/upload)
    """
    db = get_db()
    row = db.execute('SELECT * FROM files WHERE token = ?', (token,)).fetchone()

    if row is None:
        return jsonify({'error': 'Invalid or unknown token'}), 404

    if not row['is_active']:
        return jsonify({'error': 'This file link has been revoked'}), 410

    if datetime.utcnow() > datetime.fromisoformat(row['expires_at']):
        return jsonify({'error': 'This download link has expired'}), 410

    if row['max_downloads'] != 0 and row['download_count'] >= row['max_downloads']:
        return jsonify({'error': 'Maximum download limit reached for this link'}), 410

    stored_path = os.path.join(app.config['UPLOAD_FOLDER'], row['stored_filename'])
    if not os.path.exists(stored_path):
        return jsonify({'error': 'File missing on server'}), 404

    with open(stored_path, 'rb') as f:
        encrypted_data = f.read()

    try:
        file_key = crypto_utils.decrypt_bytes(row['encrypted_key'].encode(), MASTER_KEY)
        decrypted_data = crypto_utils.decrypt_bytes(encrypted_data, file_key)
    except Exception:
        return jsonify({'error': 'Failed to decrypt file (data may be corrupted or tampered with)'}), 500

    db.execute('UPDATE files SET download_count = download_count + 1 WHERE token = ?', (token,))
    db.commit()

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=row['original_filename'],
        mimetype=row['mime_type'] or 'application/octet-stream'
    )


@app.route('/api/files/<token>/info', methods=['GET'])
def file_info(token):
    """Check metadata about a shared file without consuming a download."""
    db = get_db()
    row = db.execute('SELECT * FROM files WHERE token = ?', (token,)).fetchone()
    if row is None:
        return jsonify({'error': 'Invalid or unknown token'}), 404

    return jsonify({
        'original_filename': row['original_filename'],
        'file_size_bytes': row['file_size'],
        'mime_type': row['mime_type'],
        'uploaded_at': row['uploaded_at'],
        'expires_at': row['expires_at'],
        'downloads_used': row['download_count'],
        'max_downloads': row['max_downloads'],
        'is_active': bool(row['is_active']),
        'is_expired': datetime.utcnow() > datetime.fromisoformat(row['expires_at'])
    })


@app.route('/api/files/<token>', methods=['DELETE'])
def revoke_file(token):
    """Immediately invalidate a share link and delete the encrypted file from disk."""
    db = get_db()
    row = db.execute('SELECT * FROM files WHERE token = ?', (token,)).fetchone()
    if row is None:
        return jsonify({'error': 'Invalid or unknown token'}), 404

    db.execute('UPDATE files SET is_active = 0 WHERE token = ?', (token,))
    db.commit()

    stored_path = os.path.join(app.config['UPLOAD_FOLDER'], row['stored_filename'])
    if os.path.exists(stored_path):
        os.remove(stored_path)

    return jsonify({'message': 'File revoked and deleted successfully'})


@app.errorhandler(413)
def too_large(_e):
    return jsonify({'error': 'File exceeds maximum allowed size (50MB)'}), 413


if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)

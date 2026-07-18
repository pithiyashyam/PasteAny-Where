# Secure File Sharing API — Flask + Postman

A file-sharing backend built with Flask. Files are encrypted at rest, and access is
controlled by cryptographically random, expiring, download-limited tokens. Test and
demo the whole flow through **Postman**: upload a file in one request, get back a
token/link, then use another request (or share the link) to download it.

## Project Highlights (for your intro slide)

- **Encryption** — every file gets its own random Fernet (AES-128 + HMAC) key.
  That per-file key is itself encrypted with a master key derived from the app's
  secret via PBKDF2-HMAC-SHA256 before being stored, so no plaintext file content
  or usable key ever touches disk unencrypted.
- **Security** — links expire after a configurable time, can have a max-download
  count, can be revoked instantly, and file type/size are validated on upload.
- **Token Generation** — `secrets.token_urlsafe(32)` produces a 256-bit,
  unguessable, URL-safe token per file, used as the sole credential to download it.

## 1. Setup

```bash
cd file_share_app
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

The server starts at `http://127.0.0.1:5000`. It auto-creates `file_share.db`
(SQLite) and `storage/uploads/` on first run.

> Set a real `SECRET_KEY` environment variable before any real deployment —
> the default in `config.py` is for local testing only.

## 2. Testing with Postman

### a) Health check
- **GET** `http://127.0.0.1:5000/api/health`

### b) Upload a file
- **POST** `http://127.0.0.1:5000/api/upload`
- Body → **form-data**:
  | Key | Type | Value |
  |---|---|---|
  | `file` | File | choose any file from your machine |
  | `expiry_hours` | Text (optional) | e.g. `24` |
  | `max_downloads` | Text (optional) | e.g. `5` (`0` = unlimited) |
- Response:
  ```json
  {
    "message": "File uploaded and encrypted successfully",
    "token": "BgaJR09uITtPighW_ilUl7-_glZhWVDU0tl2nMSPdyQ",
    "download_url": "http://127.0.0.1:5000/api/download/BgaJR09uITtPighW_ilUl7-_glZhWVDU0tl2nMSPdyQ",
    "original_filename": "testfile.txt",
    "file_size_bytes": 53,
    "expires_at": "2026-07-18T17:36:32.179562Z",
    "max_downloads": 2
  }
  ```
  Copy the `token` (or the whole `download_url`) — this is what you'll share with
  the "receiving" Postman client.

### c) Download the file
- **GET** `http://127.0.0.1:5000/api/download/<token>`
- Returns the original, decrypted file as an attachment (Postman will offer to
  save/preview it under the *Save Response* option).

### d) Check file status without downloading
- **GET** `http://127.0.0.1:5000/api/files/<token>/info`
- Shows filename, size, expiry, downloads used/remaining, active status.

### e) Revoke a share link early
- **DELETE** `http://127.0.0.1:5000/api/files/<token>`
- Immediately invalidates the token and deletes the encrypted file from disk.

## 3. Simulating "Postman to Postman" sharing

Because tokens are just opaque strings/URLs:
1. **Sender** runs the upload request in Postman, copies the `download_url`.
2. Sender shares that URL with the **receiver** (chat, email, another Postman
   collection, whatever channel).
3. **Receiver** pastes the URL into their own Postman GET request and downloads
   the decrypted original file — without ever needing direct access to your
   server's disk or database.

## 4. Error handling covered

| Scenario | Response |
|---|---|
| Missing/empty file | `400` |
| Disallowed file extension | `400` |
| File over 50MB | `413` |
| Unknown token | `404` |
| Expired link | `410` |
| Revoked link | `410` |
| Download limit reached | `410` |

## 5. Project structure

```
file_share_app/
├── app.py             # Flask routes
├── config.py           # App configuration
├── crypto_utils.py      # Encryption/decryption + key derivation
├── requirements.txt
├── storage/uploads/     # Encrypted files live here (never plaintext)
└── file_share.db         # SQLite metadata (created at first run)
```

## 6. Possible extensions

- Swap SQLite for Postgres/MySQL for multi-instance deployments.
- Add per-user authentication (JWT) so uploads are tied to an account.
- Add a background cleanup job to delete expired files from disk automatically.
- Add HTTPS/TLS termination (e.g. via nginx) before exposing this publicly —
  encryption at rest doesn't protect data in transit on its own.

## Author
*Pithiya Shyam*

## License
This project is licensed under the MIT License.

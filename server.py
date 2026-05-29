"""
DarkChat Server - server.py
Flask + SQLite + Socket.IO + Cloudinary
Deploy on Railway: https://darkchat-server-production.up.railway.app
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import sqlite3
import hashlib
import os
import random
import string
import jwt
import datetime
import cloudinary
import cloudinary.uploader
import cloudinary.api
import base64
import io
import re
from functools import wraps

# ─────────────────────────────────────────────
# App & Config
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'darkchat_super_secret_2024')
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',
    ping_timeout=60,
    ping_interval=25
)

# Cloudinary Config
cloudinary.config(
    cloud_name="dqg579k9q",
    api_key="10765149794639631",
    api_secret=os.environ.get('CLOUDINARY_SECRET', ''),
    secure=True
)

DB_PATH = os.environ.get('DB_PATH', 'darkchat.db')

# Online users: { user_id: socket_id }
online_users = {}

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            email       TEXT NOT NULL UNIQUE,
            password    TEXT NOT NULL,
            dc_id       TEXT NOT NULL UNIQUE,
            avatar_url  TEXT DEFAULT '',
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id      INTEGER NOT NULL,
            user2_id      INTEGER NOT NULL,
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user1_id, user2_id),
            FOREIGN KEY(user1_id) REFERENCES users(id),
            FOREIGN KEY(user2_id) REFERENCES users(id)
        )
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER NOT NULL,
            sender_id       INTEGER NOT NULL,
            content         TEXT NOT NULL,
            is_starred      INTEGER DEFAULT 0,
            read_at         DATETIME,
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id),
            FOREIGN KEY(sender_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()
    print("✅ Database initialized")

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_dc_id() -> str:
    """Generate unique DC-XXXXXX identifier"""
    chars = string.ascii_uppercase + string.digits
    conn = get_db()
    while True:
        dc_id = "DC-" + ''.join(random.choices(chars, k=6))
        row = conn.execute("SELECT id FROM users WHERE dc_id = ?", (dc_id,)).fetchone()
        if not row:
            conn.close()
            return dc_id

def generate_token(user_id: int) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token: str):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Token required'}), 401
        data = decode_token(token)
        if not data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return f(data['user_id'], *args, **kwargs)
    return decorated

def get_conv_room(conv_id: int) -> str:
    return f"conv_{conv_id}"

def get_user_room(user_id: int) -> str:
    return f"user_{user_id}"

# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json or {}
    username = data.get('username', '').strip()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'All fields required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': 'Invalid email'}), 400

    dc_id   = generate_dc_id()
    pw_hash = hash_password(password)

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, email, password, dc_id) VALUES (?, ?, ?, ?)",
            (username, email, pw_hash, dc_id)
        )
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        token = generate_token(user['id'])
        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'dc_id': user['dc_id'],
                'avatar_url': user['avatar_url']
            }
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data     = request.json or {}
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    pw_hash = hash_password(password)
    conn    = get_db()
    user    = conn.execute(
        "SELECT * FROM users WHERE email = ? AND password = ?",
        (email, pw_hash)
    ).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    token = generate_token(user['id'])
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'dc_id': user['dc_id'],
            'avatar_url': user['avatar_url']
        }
    })

@app.route('/api/me', methods=['GET'])
@token_required
def get_me(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'dc_id': user['dc_id'],
        'avatar_url': user['avatar_url']
    })

# ─────────────────────────────────────────────
# User Routes
# ─────────────────────────────────────────────
@app.route('/api/users/search', methods=['GET'])
@token_required
def search_users(user_id):
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])

    conn  = get_db()
    users = conn.execute(
        """SELECT id, username, dc_id, avatar_url FROM users
           WHERE (dc_id LIKE ? OR username LIKE ?) AND id != ?
           LIMIT 20""",
        (f'%{query}%', f'%{query}%', user_id)
    ).fetchall()
    conn.close()

    return jsonify([{
        'id': u['id'],
        'username': u['username'],
        'dc_id': u['dc_id'],
        'avatar_url': u['avatar_url']
    } for u in users])

@app.route('/api/users/<int:uid>', methods=['GET'])
@token_required
def get_user(current_user_id, uid):
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, dc_id, avatar_url FROM users WHERE id = ?", (uid,)
    ).fetchone()
    conn.close()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'dc_id': user['dc_id'],
        'avatar_url': user['avatar_url'],
        'is_online': uid in online_users
    })

@app.route('/api/users/update', methods=['PUT'])
@token_required
def update_user(user_id):
    data     = request.json or {}
    username = data.get('username', '').strip()
    if not username:
        return jsonify({'error': 'Username required'}), 400

    conn = get_db()
    conn.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
    conn.commit()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'dc_id': user['dc_id'],
        'avatar_url': user['avatar_url']
    })

@app.route('/api/users/avatar', methods=['POST'])
@token_required
def upload_avatar(user_id):
    data       = request.json or {}
    image_data = data.get('image_base64', '')

    if not image_data:
        return jsonify({'error': 'No image provided'}), 400

    try:
        # Remove data URL prefix if present
        if ',' in image_data:
            image_data = image_data.split(',')[1]

        result = cloudinary.uploader.upload(
            f"data:image/jpeg;base64,{image_data}",
            folder="darkchat_avatars",
            public_id=f"user_{user_id}",
            overwrite=True,
            resource_type="image",
            transformation=[
                {'width': 300, 'height': 300, 'crop': 'fill', 'gravity': 'face'}
            ]
        )
        avatar_url = result['secure_url']

        conn = get_db()
        conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user_id))
        conn.commit()
        conn.close()

        return jsonify({'avatar_url': avatar_url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────
# Conversations Routes
# ─────────────────────────────────────────────
@app.route('/api/conversations', methods=['GET'])
@token_required
def get_conversations(user_id):
    conn = get_db()
    rows = conn.execute(
        """
        SELECT
            c.id,
            c.user1_id,
            c.user2_id,
            c.created_at,
            m.content      AS last_message,
            m.created_at   AS last_message_at,
            m.sender_id    AS last_sender_id,
            u.username     AS other_username,
            u.dc_id        AS other_dc_id,
            u.avatar_url   AS other_avatar,
            u.id           AS other_id,
            (SELECT COUNT(*) FROM messages
             WHERE conversation_id = c.id
               AND sender_id != ?
               AND read_at IS NULL) AS unread_count
        FROM conversations c
        JOIN users u ON u.id = CASE WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END
        LEFT JOIN messages m ON m.id = (
            SELECT id FROM messages
            WHERE conversation_id = c.id
            ORDER BY created_at DESC LIMIT 1
        )
        WHERE c.user1_id = ? OR c.user2_id = ?
        ORDER BY COALESCE(m.created_at, c.created_at) DESC
        """,
        (user_id, user_id, user_id, user_id)
    ).fetchall()
    conn.close()

    return jsonify([{
        'id': r['id'],
        'other_user': {
            'id': r['other_id'],
            'username': r['other_username'],
            'dc_id': r['other_dc_id'],
            'avatar_url': r['other_avatar'],
            'is_online': r['other_id'] in online_users
        },
        'last_message': r['last_message'],
        'last_message_at': r['last_message_at'],
        'last_sender_id': r['last_sender_id'],
        'unread_count': r['unread_count'],
        'created_at': r['created_at']
    } for r in rows])

@app.route('/api/conversations', methods=['POST'])
@token_required
def create_conversation(user_id):
    data        = request.json or {}
    other_id    = data.get('other_user_id')

    if not other_id or other_id == user_id:
        return jsonify({'error': 'Invalid user'}), 400

    u1 = min(user_id, other_id)
    u2 = max(user_id, other_id)

    conn = get_db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO conversations (user1_id, user2_id) VALUES (?, ?)",
            (u1, u2)
        )
        conn.commit()
    except Exception:
        pass

    conv = conn.execute(
        "SELECT * FROM conversations WHERE user1_id = ? AND user2_id = ?",
        (u1, u2)
    ).fetchone()
    conn.close()

    return jsonify({'conversation_id': conv['id']}), 201

# ─────────────────────────────────────────────
# Messages Routes
# ─────────────────────────────────────────────
@app.route('/api/conversations/<int:conv_id>/messages', methods=['GET'])
@token_required
def get_messages(user_id, conv_id):
    conn = get_db()

    # Verify membership
    conv = conn.execute(
        "SELECT * FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        (conv_id, user_id, user_id)
    ).fetchone()
    if not conv:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    # Mark as read
    conn.execute(
        "UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
        (conv_id, user_id)
    )
    conn.commit()

    offset = int(request.args.get('offset', 0))
    limit  = int(request.args.get('limit', 50))

    msgs = conn.execute(
        """SELECT m.*, u.username, u.avatar_url
           FROM messages m
           JOIN users u ON u.id = m.sender_id
           WHERE m.conversation_id = ?
           ORDER BY m.created_at DESC
           LIMIT ? OFFSET ?""",
        (conv_id, limit, offset)
    ).fetchall()
    conn.close()

    return jsonify([{
        'id': m['id'],
        'conversation_id': m['conversation_id'],
        'sender_id': m['sender_id'],
        'sender_name': m['username'],
        'sender_avatar': m['avatar_url'],
        'content': m['content'],
        'is_starred': bool(m['is_starred']),
        'read_at': m['read_at'],
        'created_at': m['created_at']
    } for m in reversed(msgs)])

@app.route('/api/conversations/<int:conv_id>/messages', methods=['POST'])
@token_required
def send_message(user_id, conv_id):
    data    = request.json or {}
    content = data.get('content', '').strip()

    if not content:
        return jsonify({'error': 'Message cannot be empty'}), 400

    conn = get_db()
    conv = conn.execute(
        "SELECT * FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        (conv_id, user_id, user_id)
    ).fetchone()
    if not conv:
        conn.close()
        return jsonify({'error': 'Unauthorized'}), 403

    c = conn.execute(
        "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
        (conv_id, user_id, content)
    )
    conn.commit()
    msg_id = c.lastrowid

    msg = conn.execute(
        """SELECT m.*, u.username, u.avatar_url
           FROM messages m JOIN users u ON u.id = m.sender_id
           WHERE m.id = ?""",
        (msg_id,)
    ).fetchone()
    conn.close()

    msg_data = {
        'id': msg['id'],
        'conversation_id': conv_id,
        'sender_id': user_id,
        'sender_name': msg['username'],
        'sender_avatar': msg['avatar_url'],
        'content': content,
        'is_starred': False,
        'read_at': None,
        'created_at': msg['created_at']
    }

    # Emit via Socket.IO to conversation room
    socketio.emit('new_message', msg_data, room=get_conv_room(conv_id))

    # Notify the other user's personal room (for push-style notification)
    other_id = conv['user2_id'] if conv['user1_id'] == user_id else conv['user1_id']
    socketio.emit('message_notification', {
        'conversation_id': conv_id,
        'message': msg_data
    }, room=get_user_room(other_id))

    return jsonify(msg_data), 201

@app.route('/api/messages/<int:msg_id>/star', methods=['PUT'])
@token_required
def toggle_star(user_id, msg_id):
    conn = get_db()
    msg  = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
    if not msg:
        conn.close()
        return jsonify({'error': 'Message not found'}), 404

    new_star = 0 if msg['is_starred'] else 1
    conn.execute("UPDATE messages SET is_starred = ? WHERE id = ?", (new_star, msg_id))
    conn.commit()
    conn.close()
    return jsonify({'is_starred': bool(new_star)})

# ─────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────
@app.route('/', methods=['GET'])
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'app': 'DarkChat Server', 'version': '1.0.0'})

# ─────────────────────────────────────────────
# Socket.IO Events
# ─────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    print(f"[WS] Client connected: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    # Remove from online users
    user_id = None
    for uid, sid in list(online_users.items()):
        if sid == request.sid:
            user_id = uid
            break
    if user_id:
        del online_users[user_id]
        emit('user_offline', {'user_id': user_id}, broadcast=True)
    print(f"[WS] Client disconnected: {request.sid}")

@socketio.on('authenticate')
def on_authenticate(data):
    token = data.get('token', '')
    info  = decode_token(token)
    if not info:
        emit('auth_error', {'message': 'Invalid token'})
        return

    user_id = info['user_id']
    online_users[user_id] = request.sid

    # Join personal room
    join_room(get_user_room(user_id))
    emit('authenticated', {'user_id': user_id})
    emit('user_online', {'user_id': user_id}, broadcast=True)
    print(f"[WS] User {user_id} authenticated")

@socketio.on('join_conversation')
def on_join_conversation(data):
    conv_id = data.get('conversation_id')
    if conv_id:
        join_room(get_conv_room(conv_id))
        print(f"[WS] {request.sid} joined conv_{conv_id}")

@socketio.on('leave_conversation')
def on_leave_conversation(data):
    conv_id = data.get('conversation_id')
    if conv_id:
        leave_room(get_conv_room(conv_id))

@socketio.on('typing')
def on_typing(data):
    conv_id  = data.get('conversation_id')
    user_id  = data.get('user_id')
    is_typing = data.get('is_typing', False)
    if conv_id:
        emit('typing_status', {
            'user_id': user_id,
            'conversation_id': conv_id,
            'is_typing': is_typing
        }, room=get_conv_room(conv_id), include_self=False)

@socketio.on('mark_read')
def on_mark_read(data):
    conv_id = data.get('conversation_id')
    user_id = data.get('user_id')
    if conv_id and user_id:
        conn = get_db()
        conn.execute(
            "UPDATE messages SET read_at = CURRENT_TIMESTAMP WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
            (conv_id, user_id)
        )
        conn.commit()
        conn.close()
        emit('messages_read', {'conversation_id': conv_id, 'user_id': user_id},
             room=get_conv_room(conv_id), include_self=False)

# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 DarkChat Server running on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False, allow_unsafe_werkzeug=True)

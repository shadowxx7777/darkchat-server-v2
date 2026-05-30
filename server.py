"""
DarkChat Server - server.py  (FIXED - نسخة نظيفة بدون أخطاء)
Flask + SQLite + Socket.IO + Cloudinary + eventlet
"""

import eventlet
eventlet.monkey_patch()

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
import re
import logging
from functools import wraps

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("darkchat")

# ─────────────────────────────────────────────
# App & Config
# ─────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'darkchat_super_secret_2024')
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False
)

cloudinary.config(
    cloud_name=os.environ.get('CLOUDINARY_CLOUD', 'dqg579k9q'),
    api_key=os.environ.get('CLOUDINARY_KEY', '10765149794639631'),
    api_secret=os.environ.get('CLOUDINARY_SECRET', ''),
    secure=True
)

DB_PATH = os.environ.get('DB_PATH', 'darkchat.db')
online_users = {}  # { user_id: socket_id }

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    # جدول المستخدمين — كامل من البداية
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            dc_id      TEXT    NOT NULL DEFAULT '',
            avatar_url TEXT    NOT NULL DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # ✅ إضافة الأعمدة الناقصة بأمان لو الجدول قديم
    for col, definition in [
        ('dc_id',      "TEXT NOT NULL DEFAULT ''"),
        ('avatar_url', "TEXT NOT NULL DEFAULT ''"),
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
            conn.commit()
            log.info(f"✅ Added column: {col}")
        except Exception:
            pass  # العمود موجود مسبقاً

    # ✅ إنشاء UNIQUE index على dc_id بأمان
    try:
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_dcid ON users(dc_id) WHERE dc_id != ''")
        conn.commit()
    except Exception:
        pass

    c.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id   INTEGER NOT NULL,
            user2_id   INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
            content         TEXT    NOT NULL,
            is_starred      INTEGER DEFAULT 0,
            read_at         DATETIME,
            created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id),
            FOREIGN KEY(sender_id)       REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()
    log.info("✅ Database ready")

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_dc_id() -> str:
    """توليد DC-XXXXXX فريد — آمن من ناحية الـ connection"""
    chars = string.ascii_uppercase + string.digits
    for _ in range(20):  # max 20 محاولة
        dc_id = "DC-" + ''.join(random.choices(chars, k=6))
        conn = get_db()
        try:
            row = conn.execute(
                "SELECT id FROM users WHERE dc_id = ?", (dc_id,)
            ).fetchone()
            if not row:
                return dc_id
        finally:
            conn.close()
    raise RuntimeError("Failed to generate unique dc_id")

def generate_token(user_id: int) -> str:
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def decode_token(token: str):
    try:
        return jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '').strip()
        if not token:
            return jsonify({'error': 'Token required'}), 401
        data = decode_token(token)
        if not data:
            return jsonify({'error': 'Invalid or expired token'}), 401
        return f(data['user_id'], *args, **kwargs)
    return decorated

def safe_str(val) -> str:
    return val if val else ''

def user_dict(user) -> dict:
    return {
        'id':         user['id'],
        'username':   safe_str(user['username']),
        'email':      safe_str(user['email']),
        'dc_id':      safe_str(user['dc_id']),
        'avatar_url': safe_str(user['avatar_url']),
    }

def get_conv_room(conv_id):  return f"conv_{conv_id}"
def get_user_room(user_id):  return f"user_{user_id}"

# ─────────────────────────────────────────────
# Auth Routes
# ─────────────────────────────────────────────
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data     = request.get_json(force=True, silent=True) or {}
        username = data.get('username', '').strip()
        email    = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not username or not email or not password:
            return jsonify({'error': 'جميع الحقول مطلوبة'}), 400
        if len(password) < 6:
            return jsonify({'error': 'كلمة المرور 6 أحرف على الأقل'}), 400
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            return jsonify({'error': 'البريد الإلكتروني غير صحيح'}), 400
        if len(username) < 2 or len(username) > 30:
            return jsonify({'error': 'الاسم بين 2 و 30 حرف'}), 400

        dc_id   = generate_dc_id()
        pw_hash = hash_password(password)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password, dc_id) VALUES (?, ?, ?, ?)",
                (username, email, pw_hash, dc_id)
            )
            conn.commit()
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()
            if not user:
                return jsonify({'error': 'فشل إنشاء الحساب، حاول مجدداً'}), 500
            token = generate_token(user['id'])
            return jsonify({'token': token, 'user': user_dict(user)}), 201

        except sqlite3.IntegrityError as e:
            err = str(e).lower()
            if 'email' in err:
                return jsonify({'error': 'البريد الإلكتروني مستخدم مسبقاً'}), 409
            if 'dc_id' in err:
                return jsonify({'error': 'خطأ داخلي، حاول مجدداً'}), 500
            return jsonify({'error': 'خطأ في قاعدة البيانات'}), 500
        finally:
            conn.close()

    except Exception as e:
        log.error(f"register error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500


@app.route('/api/login', methods=['POST'])
def login():
    try:
        data     = request.get_json(force=True, silent=True) or {}
        email    = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'error': 'البريد وكلمة المرور مطلوبان'}), 400

        pw_hash = hash_password(password)
        conn    = get_db()
        try:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ? AND password = ?",
                (email, pw_hash)
            ).fetchone()
        finally:
            conn.close()

        if not user:
            return jsonify({'error': 'البريد أو كلمة المرور غلط'}), 401

        token = generate_token(user['id'])
        return jsonify({'token': token, 'user': user_dict(user)})

    except Exception as e:
        log.error(f"login error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500


@app.route('/api/me', methods=['GET'])
@token_required
def get_me(user_id):
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()
    if not user:
        return jsonify({'error': 'المستخدم غير موجود'}), 404
    return jsonify(user_dict(user))

# ─────────────────────────────────────────────
# User Routes
# ─────────────────────────────────────────────
@app.route('/api/users/search', methods=['GET'])
@token_required
def search_users(user_id):
    query = request.args.get('q', '').strip()
    if not query or len(query) < 2:
        return jsonify([])
    conn = get_db()
    try:
        users = conn.execute(
            """SELECT id, username, dc_id, avatar_url FROM users
               WHERE (dc_id LIKE ? OR username LIKE ?) AND id != ?
               LIMIT 20""",
            (f'%{query}%', f'%{query}%', user_id)
        ).fetchall()
    finally:
        conn.close()
    return jsonify([{
        'id':         u['id'],
        'username':   safe_str(u['username']),
        'dc_id':      safe_str(u['dc_id']),
        'avatar_url': safe_str(u['avatar_url']),
    } for u in users])


@app.route('/api/users/<int:uid>', methods=['GET'])
@token_required
def get_user(current_user_id, uid):
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT id, username, dc_id, avatar_url FROM users WHERE id = ?", (uid,)
        ).fetchone()
    finally:
        conn.close()
    if not user:
        return jsonify({'error': 'المستخدم غير موجود'}), 404
    return jsonify({
        'id':         user['id'],
        'username':   safe_str(user['username']),
        'dc_id':      safe_str(user['dc_id']),
        'avatar_url': safe_str(user['avatar_url']),
        'is_online':  uid in online_users,
    })


@app.route('/api/users/update', methods=['PUT'])
@token_required
def update_user(user_id):
    try:
        data     = request.get_json(force=True, silent=True) or {}
        username = data.get('username', '').strip()
        if not username or len(username) < 2:
            return jsonify({'error': 'الاسم مطلوب (2 أحرف على الأقل)'}), 400
        conn = get_db()
        try:
            conn.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
            conn.commit()
            user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        finally:
            conn.close()
        return jsonify(user_dict(user))
    except Exception as e:
        log.error(f"update_user error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500


@app.route('/api/users/avatar', methods=['POST'])
@token_required
def upload_avatar(user_id):
    try:
        data       = request.get_json(force=True, silent=True) or {}
        image_data = data.get('image_base64', '')
        if not image_data:
            return jsonify({'error': 'لا توجد صورة'}), 400
        if ',' in image_data:
            image_data = image_data.split(',')[1]
        result = cloudinary.uploader.upload(
            f"data:image/jpeg;base64,{image_data}",
            folder="darkchat_avatars",
            public_id=f"user_{user_id}",
            overwrite=True,
            resource_type="image",
            transformation=[{'width': 300, 'height': 300, 'crop': 'fill', 'gravity': 'face'}]
        )
        avatar_url = result['secure_url']
        conn = get_db()
        try:
            conn.execute("UPDATE users SET avatar_url = ? WHERE id = ?", (avatar_url, user_id))
            conn.commit()
        finally:
            conn.close()
        return jsonify({'avatar_url': avatar_url})
    except Exception as e:
        log.error(f"upload_avatar error: {e}")
        return jsonify({'error': str(e)}), 500

# ─────────────────────────────────────────────
# Conversations Routes
# ─────────────────────────────────────────────
@app.route('/api/conversations', methods=['GET'])
@token_required
def get_conversations(user_id):
    try:
        conn = get_db()
        try:
            rows = conn.execute(
                """
                SELECT
                    c.id, c.user1_id, c.user2_id, c.created_at,
                    m.content    AS last_message,
                    m.created_at AS last_message_at,
                    m.sender_id  AS last_sender_id,
                    u.username   AS other_username,
                    u.dc_id      AS other_dc_id,
                    u.avatar_url AS other_avatar,
                    u.id         AS other_id,
                    (SELECT COUNT(*) FROM messages
                     WHERE conversation_id = c.id
                       AND sender_id != ?
                       AND read_at IS NULL) AS unread_count
                FROM conversations c
                JOIN users u ON u.id = CASE
                    WHEN c.user1_id = ? THEN c.user2_id ELSE c.user1_id END
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
        finally:
            conn.close()

        return jsonify([{
            'id': r['id'],
            'other_user': {
                'id':         r['other_id'],
                'username':   safe_str(r['other_username']),
                'dc_id':      safe_str(r['other_dc_id']),
                'avatar_url': safe_str(r['other_avatar']),
                'is_online':  r['other_id'] in online_users,
            },
            'last_message':    r['last_message'],
            'last_message_at': r['last_message_at'],
            'last_sender_id':  r['last_sender_id'],
            'unread_count':    r['unread_count'] or 0,
            'created_at':      r['created_at'],
        } for r in rows])
    except Exception as e:
        log.error(f"get_conversations error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500


@app.route('/api/conversations', methods=['POST'])
@token_required
def create_conversation(user_id):
    try:
        data     = request.get_json(force=True, silent=True) or {}
        other_id = data.get('other_user_id')
        if not other_id:
            return jsonify({'error': 'other_user_id مطلوب'}), 400
        other_id = int(other_id)
        if other_id == user_id:
            return jsonify({'error': 'لا تستطيع محادثة نفسك'}), 400

        u1, u2 = min(user_id, other_id), max(user_id, other_id)
        conn = get_db()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO conversations (user1_id, user2_id) VALUES (?, ?)",
                (u1, u2)
            )
            conn.commit()
            conv = conn.execute(
                "SELECT id FROM conversations WHERE user1_id = ? AND user2_id = ?",
                (u1, u2)
            ).fetchone()
        finally:
            conn.close()
        return jsonify({'conversation_id': conv['id']}), 201
    except Exception as e:
        log.error(f"create_conversation error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500

# ─────────────────────────────────────────────
# Messages Routes
# ─────────────────────────────────────────────
@app.route('/api/conversations/<int:conv_id>/messages', methods=['GET'])
@token_required
def get_messages(user_id, conv_id):
    try:
        conn = get_db()
        try:
            conv = conn.execute(
                "SELECT * FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
                (conv_id, user_id, user_id)
            ).fetchone()
            if not conv:
                return jsonify({'error': 'غير مصرح'}), 403

            conn.execute(
                """UPDATE messages SET read_at = CURRENT_TIMESTAMP
                   WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL""",
                (conv_id, user_id)
            )
            conn.commit()

            offset = max(0, int(request.args.get('offset', 0)))
            limit  = min(100, max(1, int(request.args.get('limit', 50))))

            msgs = conn.execute(
                """SELECT m.id, m.conversation_id, m.sender_id, m.content,
                          m.is_starred, m.read_at, m.created_at,
                          u.username AS sender_name, u.avatar_url AS sender_avatar
                   FROM messages m
                   JOIN users u ON u.id = m.sender_id
                   WHERE m.conversation_id = ?
                   ORDER BY m.created_at DESC
                   LIMIT ? OFFSET ?""",
                (conv_id, limit, offset)
            ).fetchall()
        finally:
            conn.close()

        return jsonify([{
            'id':              m['id'],
            'conversation_id': m['conversation_id'],
            'sender_id':       m['sender_id'],
            'sender_name':     safe_str(m['sender_name']),
            'sender_avatar':   safe_str(m['sender_avatar']),
            'content':         m['content'],
            'is_starred':      bool(m['is_starred']),
            'read_at':         m['read_at'],
            'created_at':      m['created_at'],
        } for m in reversed(msgs)])
    except Exception as e:
        log.error(f"get_messages error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500


@app.route('/api/conversations/<int:conv_id>/messages', methods=['POST'])
@token_required
def send_message(user_id, conv_id):
    try:
        data    = request.get_json(force=True, silent=True) or {}
        content = data.get('content', '').strip()
        if not content:
            return jsonify({'error': 'الرسالة فارغة'}), 400

        conn = get_db()
        try:
            conv = conn.execute(
                "SELECT * FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
                (conv_id, user_id, user_id)
            ).fetchone()
            if not conv:
                return jsonify({'error': 'غير مصرح'}), 403

            cur = conn.execute(
                "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
                (conv_id, user_id, content)
            )
            conn.commit()
            msg_id = cur.lastrowid

            msg = conn.execute(
                """SELECT m.*, u.username AS sender_name, u.avatar_url AS sender_avatar
                   FROM messages m JOIN users u ON u.id = m.sender_id
                   WHERE m.id = ?""",
                (msg_id,)
            ).fetchone()
        finally:
            conn.close()

        msg_data = {
            'id':              msg['id'],
            'conversation_id': conv_id,
            'sender_id':       user_id,
            'sender_name':     safe_str(msg['sender_name']),
            'sender_avatar':   safe_str(msg['sender_avatar']),
            'content':         content,
            'is_starred':      False,
            'read_at':         None,
            'created_at':      msg['created_at'],
        }

        socketio.emit('new_message', msg_data, room=get_conv_room(conv_id))
        other_id = conv['user2_id'] if conv['user1_id'] == user_id else conv['user1_id']
        socketio.emit('message_notification',
                      {'conversation_id': conv_id, 'message': msg_data},
                      room=get_user_room(other_id))

        return jsonify(msg_data), 201
    except Exception as e:
        log.error(f"send_message error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500


@app.route('/api/messages/<int:msg_id>/star', methods=['PUT'])
@token_required
def toggle_star(user_id, msg_id):
    try:
        conn = get_db()
        try:
            msg = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
            if not msg:
                return jsonify({'error': 'الرسالة غير موجودة'}), 404
            new_star = 0 if msg['is_starred'] else 1
            conn.execute("UPDATE messages SET is_starred = ? WHERE id = ?", (new_star, msg_id))
            conn.commit()
        finally:
            conn.close()
        return jsonify({'is_starred': bool(new_star)})
    except Exception as e:
        log.error(f"toggle_star error: {e}")
        return jsonify({'error': 'خطأ في السيرفر'}), 500

# ─────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────
@app.route('/', methods=['GET'])
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'app': 'DarkChat', 'version': '2.0.0'})

# ─────────────────────────────────────────────
# Socket.IO
# ─────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    log.info(f"[WS] connect: {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    uid_found = None
    for uid, sid in list(online_users.items()):
        if sid == request.sid:
            uid_found = uid
            break
    if uid_found is not None:
        del online_users[uid_found]
        emit('user_offline', {'user_id': uid_found}, broadcast=True)
    log.info(f"[WS] disconnect: {request.sid}")

@socketio.on('authenticate')
def on_authenticate(data):
    token = (data or {}).get('token', '')
    info  = decode_token(token)
    if not info:
        emit('auth_error', {'message': 'Invalid token'})
        return
    user_id = info['user_id']
    online_users[user_id] = request.sid
    join_room(get_user_room(user_id))
    emit('authenticated', {'user_id': user_id})
    emit('user_online', {'user_id': user_id}, broadcast=True)

@socketio.on('join_conversation')
def on_join_conversation(data):
    conv_id = (data or {}).get('conversation_id')
    if conv_id:
        join_room(get_conv_room(conv_id))

@socketio.on('leave_conversation')
def on_leave_conversation(data):
    conv_id = (data or {}).get('conversation_id')
    if conv_id:
        leave_room(get_conv_room(conv_id))

@socketio.on('typing')
def on_typing(data):
    data = data or {}
    conv_id   = data.get('conversation_id')
    user_id   = data.get('user_id')
    is_typing = data.get('is_typing', False)
    if conv_id:
        emit('typing_status', {
            'user_id': user_id,
            'conversation_id': conv_id,
            'is_typing': is_typing,
        }, room=get_conv_room(conv_id), include_self=False)

@socketio.on('mark_read')
def on_mark_read(data):
    data    = data or {}
    conv_id = data.get('conversation_id')
    user_id = data.get('user_id')
    if conv_id and user_id:
        conn = get_db()
        try:
            conn.execute(
                """UPDATE messages SET read_at = CURRENT_TIMESTAMP
                   WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL""",
                (conv_id, user_id)
            )
            conn.commit()
        finally:
            conn.close()
        emit('messages_read', {'conversation_id': conv_id, 'user_id': user_id},
             room=get_conv_room(conv_id), include_self=False)

# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
init_db()  # ✅ يشتغل دائماً سواء gunicorn أو python مباشر

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    log.info(f"🚀 DarkChat running on port {port}")
    socketio.run(app, host='0.0.0.0', port=port, debug=False)

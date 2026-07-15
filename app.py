"""
وكالة الدواحي للسفر والسياحة — سيرفر Flask + قاعدة بيانات SQLite حقيقية
يعمل بالكامل محلياً على الهاتف عبر Termux، بدون أي اتصال إنترنت خارجي.

تشغيل:
    pip install flask werkzeug
    python app.py

ثم افتح المتصفح على:
    http://127.0.0.1:5000
"""

import os
import sqlite3
import uuid
from datetime import datetime, date

from flask import (
    Flask, request, jsonify, session, send_from_directory, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "dawahi.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "passports")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
app.secret_key = "غيّر-هذا-المفتاح-لاحقاً-dawahi-secret"  # يفضل تغييره قبل النشر الحقيقي
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # حد أقصى 8MB لصورة الجواز


# ---------------------------------------------------------------------------
# قاعدة البيانات
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            country TEXT NOT NULL,
            passport_issue TEXT NOT NULL,
            passport_expiry TEXT NOT NULL,
            passport_file TEXT,
            invite_code TEXT,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL,
            kind TEXT NOT NULL,               -- 'flight' أو 'hotel'
            title TEXT NOT NULL,
            details TEXT,
            price INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'مؤكدة',
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# أدوات مساعدة
# ---------------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return row


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({"ok": False, "error": "يجب تسجيل الدخول أولاً"}), 401
        return view(*args, **kwargs)

    return wrapped


def gen_booking_code():
    return "DWH-" + uuid.uuid4().hex[:10].upper()


# ---------------------------------------------------------------------------
# صفحات HTML (نفس الملفات الأصلية بدون أي تعديل في التسمية)
# ---------------------------------------------------------------------------
@app.route("/")
def root():
    return send_from_directory(BASE_DIR, "index.html")


# ---------------------------------------------------------------------------
# API: تسجيل حساب جديد
# ---------------------------------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    f = request.form
    username = f.get("username", "").strip()
    email = f.get("email", "").strip().lower()
    phone = f.get("phone", "").strip()
    country = f.get("country", "").strip()
    passport_issue = f.get("passport_issue", "")
    passport_expiry = f.get("passport_expiry", "")
    invite_code = f.get("code", "").strip()
    pw1 = f.get("password1", "")
    pw2 = f.get("password2", "")

    if not all([username, email, phone, country, passport_issue, passport_expiry, pw1, pw2]):
        return jsonify({"ok": False, "error": "الرجاء تعبئة جميع الحقول المطلوبة"}), 400
    if pw1 != pw2:
        return jsonify({"ok": False, "error": "كلمتا المرور غير متطابقتين"}), 400
    if len(pw1) < 6:
        return jsonify({"ok": False, "error": "كلمة المرور يجب أن تكون 6 أحرف على الأقل"}), 400

    try:
        issue_d = datetime.strptime(passport_issue, "%Y-%m-%d").date()
        expiry_d = datetime.strptime(passport_expiry, "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"ok": False, "error": "صيغة التاريخ غير صحيحة"}), 400

    if expiry_d < date.today():
        return jsonify({"ok": False, "error": "جواز السفر منتهي الصلاحية! الرجاء استخدام جواز سفر ساري."}), 400
    if issue_d > expiry_d:
        return jsonify({"ok": False, "error": "تاريخ الإصدار يجب أن يكون قبل تاريخ الانتهاء"}), 400

    db = get_db()
    if db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
        return jsonify({"ok": False, "error": "هذا البريد الإلكتروني مسجل بالفعل"}), 400

    # حفظ صورة الجواز
    passport_filename = None
    file = request.files.get("passport")
    if file and file.filename:
        ext = os.path.splitext(file.filename)[1]
        passport_filename = f"{uuid.uuid4().hex}{ext}"
        file.save(os.path.join(UPLOAD_DIR, secure_filename(passport_filename)))

    db.execute(
        """INSERT INTO users
           (username, email, phone, country, passport_issue, passport_expiry,
            passport_file, invite_code, password_hash, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (
            username, email, phone, country, passport_issue, passport_expiry,
            passport_filename, invite_code, generate_password_hash(pw1),
            datetime.now().isoformat(),
        ),
    )
    db.commit()
    return jsonify({"ok": True, "message": "تم إنشاء الحساب بنجاح"})


# ---------------------------------------------------------------------------
# API: تسجيل الدخول / الخروج
# ---------------------------------------------------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"ok": False, "error": "البريد الإلكتروني أو كلمة المرور غير صحيحة"}), 401

    session["user_id"] = user["id"]
    return jsonify({"ok": True, "username": user["username"]})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/session", methods=["GET"])
def api_session():
    user = current_user()
    if not user:
        return jsonify({"ok": True, "logged_in": False})
    return jsonify({"ok": True, "logged_in": True, "username": user["username"], "email": user["email"]})


# ---------------------------------------------------------------------------
# API: الحجوزات
# ---------------------------------------------------------------------------
@app.route("/api/book", methods=["POST"])
@login_required
def api_book():
    user = current_user()
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")          # 'flight' or 'hotel'
    title = data.get("title", "")
    details = data.get("details", "")
    price = int(data.get("price", 0))

    if kind not in ("flight", "hotel") or not title or price <= 0:
        return jsonify({"ok": False, "error": "بيانات الحجز غير صحيحة"}), 400

    code = gen_booking_code()
    db = get_db()
    db.execute(
        """INSERT INTO bookings (code, user_id, kind, title, details, price, status, created_at)
           VALUES (?,?,?,?,?,?,?,?)""",
        (code, user["id"], kind, title, details, price, "مؤكدة", datetime.now().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True, "code": code})


@app.route("/api/bookings", methods=["GET"])
@login_required
def api_bookings():
    user = current_user()
    rows = get_db().execute(
        "SELECT * FROM bookings WHERE user_id = ? ORDER BY id DESC", (user["id"],)
    ).fetchall()
    return jsonify({"ok": True, "bookings": [dict(r) for r in rows]})


@app.route("/api/booking/<code>", methods=["GET"])
@login_required
def api_booking_detail(code):
    user = current_user()
    row = get_db().execute(
        "SELECT * FROM bookings WHERE code = ? AND user_id = ?", (code, user["id"])
    ).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "الحجز غير موجود"}), 404
    return jsonify({"ok": True, "booking": dict(row)})


@app.route("/api/booking/<code>/cancel", methods=["POST"])
@login_required
def api_booking_cancel(code):
    user = current_user()
    db = get_db()
    row = db.execute(
        "SELECT * FROM bookings WHERE code = ? AND user_id = ?", (code, user["id"])
    ).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "الحجز غير موجود"}), 404
    db.execute("UPDATE bookings SET status = 'ملغاة' WHERE id = ?", (row["id"],))
    db.commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    print("قاعدة البيانات جاهزة عند:", DB_PATH)
    print("افتح المتصفح على: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)

from flask import Flask, render_template, request, redirect, session, flash, url_for, jsonify, send_from_directory
from typing import Optional
import sqlite3
import os
from werkzeug.utils import secure_filename
from datetime import datetime
from ai_models import ModelService
from utils_forensics import (
    compute_sha256,
    read_image_metadata,
    detect_ai_signatures_from_metadata,
    read_basic_video_metadata,
    detect_ai_signatures_for_video_meta,
)
from datetime import datetime as _dt
import atexit
import threading
import time
import secrets
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "realitycheck_secret"

# Simple CSRF protection
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    return token and session.get('csrf_token') == token

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'webm'}
ALLOWED_AUDIO_EXTENSIONS = {'mp3', 'wav', 'm4a', 'ogg', 'flac'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Create upload directories if they don't exist
try:
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
except OSError as e:
    print(f"Warning: Could not create upload directory {UPLOAD_FOLDER}: {e}")
    # Fallback to a temporary directory
    import tempfile
    UPLOAD_FOLDER = tempfile.mkdtemp()
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    print(f"Using temporary upload directory: {UPLOAD_FOLDER}")

# Initialize optional AI model service (uses env vars and falls back gracefully)
model_service = ModelService()

# File cleanup function
def cleanup_old_files():
    """Remove uploaded files older than 24 hours to prevent disk space issues."""
    if not os.path.exists(UPLOAD_FOLDER):
        return
    
    try:
        current_time = time.time()
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                file_age = current_time - os.path.getmtime(file_path)
                # Remove files older than 24 hours (86400 seconds)
                if file_age > 86400:
                    try:
                        os.remove(file_path)
                        print(f"Cleaned up old file: {filename}")
                    except OSError as e:
                        print(f"Could not remove file {filename}: {e}")
    except Exception as e:
        print(f"Error during file cleanup: {e}")

# Start cleanup thread
def start_cleanup_thread():
    def cleanup_worker():
        while True:
            cleanup_old_files()
            time.sleep(3600)  # Run cleanup every hour
    
    cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
    cleanup_thread.start()

# Register cleanup on app exit
atexit.register(cleanup_old_files)

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def allowed_video_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS

def allowed_audio_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_AUDIO_EXTENSIONS

# --------- Very simple placeholder scoring to label AI vs Human ---------
def compute_ai_probability_for_text(input_text: str) -> float:
    words = [w for w in input_text.split() if w]
    if not words:
        return 0.5
    unique_ratio = len(set(words)) / len(words)
    avg_len = sum(len(w) for w in words) / len(words)
    repetitive = 1.0 if any(words.count(w) > 3 for w in set(words)) else 0.0
    # Heuristic: lower uniqueness, higher avg length, and repetitions push towards AI
    score = (1.0 - unique_ratio) * 0.55 + (1.0 if avg_len > 5.5 else 0.0) * 0.25 + repetitive * 0.2
    return max(0.01, min(0.99, score))

def compute_ai_probability_for_file(filepath: str) -> float:
    try:
        size_kb = os.path.getsize(filepath) / 1024.0
        # Pseudo signal: map size to a stable probability bucket for demo purposes
        bucket = int(size_kb) % 100
        return max(0.05, min(0.95, bucket / 100.0))
    except Exception:
        return 0.5

# ---------- ADMIN CREDENTIALS (2 predefined admins) ----------
ADMINS = {
    "admin1@realitycheck.com": "admin123",
    "admin2@realitycheck.com": "superadmin"
}

# ---------- DATABASE SETUP ----------
def init_db():
    try:
        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        email TEXT,
                        password TEXT,
                        gender TEXT,
                        mobile TEXT,
                        role TEXT DEFAULT 'user'
                    )''')
        conn.commit()
        conn.close()
        print("Database initialized successfully")
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
        raise


# ---------- ROUTES ----------
@app.route('/')
def index():
    return render_template('index.html')

# ---------- REGISTER ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        gender = request.form.get('gender', '').strip()
        mobile = request.form['mobile'].strip()

        # Validation
        if not username or not email or not password:
            flash("Please fill in all required fields.", "danger")
            return render_template('register.html')
        
        if len(username) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return render_template('register.html')
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template('register.html')

        # Hash the password before storing
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        try:
            # Check if username or email already exists
            cur.execute("SELECT username, email FROM users WHERE username=? OR email=?", (username, email))
            existing = cur.fetchone()
            if existing:
                if existing[0] == username:
                    flash("Username already exists! Please choose a different one.", "danger")
                else:
                    flash("Email already registered! Please use a different email.", "danger")
                return render_template('register.html')
            
            cur.execute("INSERT INTO users (username, email, password, gender, mobile) VALUES (?, ?, ?, ?, ?)",
                        (username, email, hashed_password, gender, mobile))
            conn.commit()
            flash("Registration successful! You can now login with your credentials.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            flash(f"Registration failed: {str(e)}", "danger")
        except Exception as e:
            flash(f"An error occurred during registration: {str(e)}", "danger")
        finally:
            conn.close()
    return render_template('register.html')


# ---------- USER LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template('login.html')

        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()

        if user:
            stored_password = user[3]  # password field
            
            # Check if password is hashed (starts with scrypt: or pbkdf2:) or plain text
            if stored_password.startswith(('scrypt:', 'pbkdf2:', 'argon2:')):
                # Hashed password
                password_valid = check_password_hash(stored_password, password)
            else:
                # Legacy plain text password - compare directly and then hash it
                password_valid = (stored_password == password)
                if password_valid:
                    # Upgrade to hashed password
                    hashed_password = generate_password_hash(password)
                    conn = sqlite3.connect('database.db')
                    cur = conn.cursor()
                    cur.execute("UPDATE users SET password = ? WHERE id = ?", (hashed_password, user[0]))
                    conn.commit()
                    conn.close()
                    print(f"Upgraded password for user: {username}")
            
            if password_valid:
                session['username'] = user[1]
                session['role'] = user[6] if user[6] else 'user'
                if user[6] == 'admin':
                    session['admin'] = user[1]
                    flash(f"Welcome back, Admin {username}!", "success")
                    return redirect(url_for('admin'))
                else:
                    flash(f"Welcome back, {username}!", "success")
                    return redirect(url_for('main'))
            else:
                flash("Invalid username or password.", "danger")
        else:
            flash("Invalid username or password.", "danger")
    
    return render_template('login.html')

# ---------- ADMIN LOGIN ----------
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email in ADMINS and ADMINS[email] == password:
            session['admin'] = email
            flash("Admin login successful!", "success")
            return redirect(url_for('admin'))
        else:
            flash("Invalid admin credentials!", "danger")

    return render_template('admin_login.html')

# ---------- ADMIN DASHBOARD ----------
@app.route('/admin')
def admin():
    if 'admin' in session:
        conn = sqlite3.connect('database.db')
        cur = conn.cursor()
        cur.execute("SELECT id, username, email, role, gender, mobile FROM users")
        users = cur.fetchall()
        conn.close()
        return render_template('admin.html', users=users)
    else:
        return redirect(url_for('admin_login'))

# ---------- ADMIN ACTIONS (Promote, Demote, Delete) ----------
@app.route('/admin/promote/<int:user_id>', methods=['POST'])
def promote_user(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    try:
        cur.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
        conn.commit()
        if cur.rowcount > 0:
            conn.close()
            return jsonify({'success': True})
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/demote/<int:user_id>', methods=['POST'])
def demote_user(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    try:
        # Get the user's email to check if they're a predefined admin
        cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if user and user[0] in ADMINS:
            conn.close()
            return jsonify({'success': False, 'error': 'Cannot demote predefined admin'}), 400
        
        cur.execute("UPDATE users SET role = 'user' WHERE id = ?", (user_id,))
        conn.commit()
        if cur.rowcount > 0:
            conn.close()
            return jsonify({'success': True})
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'admin' not in session:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    try:
        # Get the user's email to check if they're a predefined admin
        cur.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        
        if user and user[0] in ADMINS:
            conn.close()
            return jsonify({'success': False, 'error': 'Cannot delete predefined admin'}), 400
        
        # Check if trying to delete themselves (if logged in as database admin)
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user_data = cur.fetchone()
        if user_data and session.get('username') == user_data[0]:
            conn.close()
            return jsonify({'success': False, 'error': 'Cannot delete your own account'}), 400
        
        cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if cur.rowcount > 0:
            conn.close()
            return jsonify({'success': True})
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

# ---------- MAIN USER PAGE ----------
@app.route('/main')
def main():
    if 'username' in session:
        return render_template('main.html', username=session['username'])
    else:
        flash("Please login to access RealityCheck.", "warning")
        return redirect(url_for('login'))


# ---------- LOGOUT ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for('index'))

# -----------------------------
# Verification Routes
# -----------------------------

@app.route('/verify_text', methods=['GET', 'POST'])
def verify_text():
    if 'username' not in session:
        flash("Please login to access RealityCheck.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        input_text = request.form['input_text']
        # Try model first; fallback to heuristic
        prob = None
        if model_service.can_text:
            prob = model_service.detect_text(input_text)
        if prob is None:
            # Placeholder heuristic to label AI vs Human
            prob = compute_ai_probability_for_text(input_text)
        score = int(round(prob * 100))
        is_ai = prob >= 0.6
        result_label = 'AI-generated' if is_ai else 'Human-created'
        result = f"This text appears to be {result_label}."
        return render_template('verify_text_result.html', text=input_text, result=result, score=score, is_ai=is_ai, result_label=result_label)
    return render_template('verify_text.html')


@app.route('/verify_image', methods=['GET', 'POST'])
def verify_image():
    if 'username' not in session:
        flash("Please login to access RealityCheck.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'image' not in request.files:
            flash("No image file provided.", "danger")
            return redirect(url_for('verify_image'))
        
        image = request.files['image']
        if image.filename == '':
            flash("No image file selected.", "danger")
            return redirect(url_for('verify_image'))
        
        if image and allowed_image_file(image.filename):
            # Save the file
            filename = secure_filename(image.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            
            # Try image model first; fallback to heuristic
            prob = None
            if model_service.can_image:
                prob = model_service.detect_image(filepath)
            if prob is None:
                # Placeholder heuristic to label AI vs Human
                prob = compute_ai_probability_for_file(filepath)
            score = int(round(prob * 100))
            is_ai = prob >= 0.6
            result_label = 'AI-generated' if is_ai else 'Human-created'
            result = f"This image appears to be {result_label}."
            return render_template('verify_image_result.html', 
                                 result=result,
                                 score=score,
                                 is_ai=is_ai,
                                 result_label=result_label,
                                 image_filename=f"/static/uploads/{filename}")
        else:
            flash("Invalid file type. Please upload an image file (PNG, JPG, JPEG, GIF, WEBP).", "danger")
            return redirect(url_for('verify_image'))
    
    return render_template('verify_image.html')


@app.route('/verify_video', methods=['GET', 'POST'])
def verify_video():
    if 'username' not in session:
        flash("Please login to access RealityCheck.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'video' not in request.files:
            flash("No video file provided.", "danger")
            return redirect(url_for('verify_video'))
        
        video = request.files['video']
        if video.filename == '':
            flash("No video file selected.", "danger")
            return redirect(url_for('verify_video'))
        
        if video and allowed_video_file(video.filename):
            # Save the file
            filename = secure_filename(video.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            video.save(filepath)
            
            # Try video model (frame-based) first; fallback to heuristic
            prob = None
            if model_service.can_video:
                prob = model_service.detect_video(filepath)
            if prob is None:
                # Placeholder heuristic to label AI vs Human
                prob = compute_ai_probability_for_file(filepath)
            score = int(round(prob * 100))
            is_ai = prob >= 0.6
            result_label = 'AI-generated' if is_ai else 'Human-created'
            result = f"This video appears to be {result_label}."
            return render_template('verify_video_result.html', 
                                 result=result,
                                 score=score,
                                 is_ai=is_ai,
                                 result_label=result_label,
                                 video_filename=f"/static/uploads/{filename}")
        else:
            flash("Invalid file type. Please upload a video file (MP4, AVI, MOV, MKV, WEBM).", "danger")
            return redirect(url_for('verify_video'))
    
    return render_template('verify_video.html')


@app.route('/verify_audio', methods=['GET', 'POST'])
def verify_audio():
    if 'username' not in session:
        flash("Please login to access RealityCheck.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        if 'audio' not in request.files:
            flash("No audio file provided.", "danger")
            return redirect(url_for('verify_audio'))
        audio = request.files['audio']
        if audio.filename == '':
            flash("No audio file selected.", "danger")
            return redirect(url_for('verify_audio'))
        if audio and allowed_audio_file(audio.filename):
            filename = secure_filename(audio.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            audio.save(filepath)

            # Try audio model first; fallback to heuristic
            prob = None
            if model_service.can_audio:
                prob = model_service.detect_audio(filepath)
            if prob is None:
                # Heuristic placeholder for audio (reuse file-based heuristic)
                prob = compute_ai_probability_for_file(filepath)
            score = int(round(prob * 100))
            is_ai = prob >= 0.6
            result_label = 'AI-generated' if is_ai else 'Human-created'
            result = f"This audio appears to be {result_label}."

            return render_template('verify_audio_result.html',
                                   result=result,
                                   score=score,
                                   is_ai=is_ai,
                                   result_label=result_label,
                                   audio_filename=f"/static/uploads/{filename}")
        else:
            flash("Invalid file type. Please upload an audio file (MP3, WAV, M4A, OGG, FLAC).", "danger")
            return redirect(url_for('verify_audio'))
    return render_template('verify_audio.html')


@app.route('/report')
def report():
    # Simple chain-of-evidence report built from query params
    report_type = request.args.get('type', 'unknown')
    score = request.args.get('score')
    label = request.args.get('label')
    sha = request.args.get('sha')
    image_sha = request.args.get('image_sha')
    combined_score = request.args.get('combined_score')
    combined_label = request.args.get('combined_label')

    def to_int_or_none(v):
        try:
            return int(v) if v is not None else None
        except Exception:
            return None

    return render_template(
        'report.html',
        report_type=report_type,
        score=to_int_or_none(score),
        label=label,
        sha=sha,
        image_sha=image_sha,
        combined_score=to_int_or_none(combined_score),
        combined_label=combined_label,
        timestamp=_dt.now().strftime('%Y-%m-%d %H:%M:%S')
    )


# -------- Combined Image + Text Verification --------
@app.route('/verify_combo', methods=['GET', 'POST'])
def verify_combo():
    if 'username' not in session:
        flash("Please login to access RealityCheck.", "warning")
        return redirect(url_for('login'))
    if request.method == 'POST':
        input_text = request.form.get('input_text', '').strip()
        image = request.files.get('image')

        text_prob = None
        if input_text:
            if model_service.can_text:
                text_prob = model_service.detect_text(input_text)
            if text_prob is None:
                text_prob = compute_ai_probability_for_text(input_text)

        image_prob = None
        image_url = None
        if image and image.filename and allowed_image_file(image.filename):
            filename = secure_filename(image.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            if model_service.can_image:
                image_prob = model_service.detect_image(filepath)
            if image_prob is None:
                image_prob = compute_ai_probability_for_file(filepath)
            image_url = f"/static/uploads/{filename}"

        # Combine verdicts: simple average when both present
        combined_prob = None
        present = [p for p in [text_prob, image_prob] if p is not None]
        if present:
            combined_prob = sum(present) / len(present)

        def label_from_prob(p: Optional[float]):
            if p is None:
                return 'N/A'
            return 'AI-generated' if p >= 0.6 else 'Human-created'

        return render_template(
            'verify_combo_result.html',
            text=input_text,
            text_score=None if text_prob is None else int(round(text_prob * 100)),
            text_label=label_from_prob(text_prob),
            image_score=None if image_prob is None else int(round(image_prob * 100)),
            image_label=label_from_prob(image_prob),
            combined_score=None if combined_prob is None else int(round(combined_prob * 100)),
            combined_label=label_from_prob(combined_prob),
            image_filename=image_url,
        )
    return render_template('verify_combo.html')


# (Removed threshold setter and URL verification per request)



# ---------- MAIN ----------
if __name__ == '__main__':
    init_db()
    start_cleanup_thread()
    app.run(debug=True)

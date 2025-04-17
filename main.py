from flask import Flask, flash, render_template, request, redirect, session, send_file, url_for, make_response, jsonify
import os
import sqlite3
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
import base64
import hashlib
from cryptography.fernet import Fernet
import io
from datetime import datetime
import csv
import mimetypes

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'encrypted_uploads'
HISTORY_DB = 'history.db'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def init_db():
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT)''')
        conn.commit()

    with sqlite3.connect(HISTORY_DB) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        filename TEXT,
                        timestamp TEXT,
                        decryption_timestamp TEXT)''')
        conn.commit()

def encrypt_file(data, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    encrypted = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted)

def decrypt_file(data, password):
    key = hashlib.sha256(password.encode()).digest()
    decoded = base64.b64decode(data)
    nonce = decoded[:16]
    tag = decoded[16:32]
    ciphertext = decoded[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('users.db') as conn:
            try:
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                conn.commit()
                return redirect(url_for('login'))
            except:
                return "Username already exists."
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            user = cursor.fetchone()
            if user:
                session['username'] = username
                return redirect(url_for('dashboard'))
            else:
                return "Invalid credentials."
    return render_template('login.html')

def get_file_list():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return [f for f in files if f.endswith('.enc')]

def save_encryption_history(username, filename):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(HISTORY_DB) as conn:
        conn.execute("INSERT INTO history (username, filename, timestamp, decryption_timestamp) VALUES (?, ?, ?, NULL)", (username, filename, timestamp))
        conn.commit()

def update_decryption_timestamp(username, filename):
    decryption_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(HISTORY_DB) as conn:
        conn.execute("UPDATE history SET decryption_timestamp = ? WHERE username = ? AND filename = ? AND decryption_timestamp IS NULL", (decryption_timestamp, username, filename))
        conn.commit()

def load_encryption_history(username):
    with sqlite3.connect(HISTORY_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT filename, timestamp, decryption_timestamp FROM history WHERE username = ? ORDER BY id DESC", (username,))
        rows = cursor.fetchall()
        return [{'filename': r[0], 'timestamp': r[1], 'decryption_timestamp': r[2]} for r in rows]
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))

    search_query = request.args.get('search', '').lower()
    files = get_file_list()
    history = load_encryption_history(session['username'])

    # Filter files and history based on search query
    if search_query:
        files = [f for f in files if search_query in f.lower()]
        history = [h for h in history if search_query in h['filename'].lower() or search_query in h['timestamp'].lower() or (h['decryption_timestamp'] and search_query in h['decryption_timestamp'].lower())]

    # Get Fernet key (if it's available for the user)
    fernet_key = None  # You can fetch the Fernet key from the user record or another source

    return render_template('dashboard.html', username=session['username'], files=files, history=history, search_query=search_query, fernet_key=fernet_key)
@app.route('/upload', methods=['POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('index'))

    file = request.files['file']
    new_filename = request.form.get('new_filename', '').strip()
    aes_key = request.form.get('aes_password', '').strip()

    if file and aes_key:
        original_filename = secure_filename(file.filename)
        filename = secure_filename(new_filename) if new_filename else original_filename

        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], filename + ".enc")

        data = file.read()
        aes_encrypted = encrypt_file(data, aes_key)

        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)
        final_encrypted = fernet.encrypt(aes_encrypted)

        with open(encrypted_path, 'wb') as f:
            f.write(final_encrypted)

        save_encryption_history(session['username'], filename)

        flash("✅ File uploaded and encrypted successfully.", "success")
        flash(f"🔑 Your Fernet Key (copy & save it safely): {fernet_key.decode()}", "info")

        return redirect(url_for('dashboard'))

    flash("❌ Both file and AES password are required.", "error")
    return redirect(url_for('dashboard'))

@app.route('/delete/<filename>', methods=['POST'])
def delete(filename):
    if 'username' not in session:
        return redirect(url_for('index'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash('✅ File deleted successfully.', 'success')
    else:
        flash('❌ File not found.', 'error')

    return redirect(url_for('dashboard'))

@app.route('/download/<filename>', methods=['POST'])
def download(filename):
    if 'username' not in session:
        return redirect(url_for('index'))

    fernet_key = request.form.get('fernet_key', '').strip()
    aes_password = request.form.get('aes_key', '').strip()

    if not fernet_key or not aes_password:
        flash("❌ Both Fernet key and AES password are required.", "error")
        return redirect(url_for('dashboard'))

    try:
        fernet = Fernet(fernet_key.encode())
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(file_path):
            flash("❌ Encrypted file not found.", "error")
            return redirect(url_for('dashboard'))

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        intermediate_data = fernet.decrypt(encrypted_data)
        decrypted_data = decrypt_file(intermediate_data, aes_password)

        update_decryption_timestamp(session['username'], filename.replace('.enc', ''))

        decrypted_stream = io.BytesIO(decrypted_data)
        decrypted_stream.seek(0)
        original_filename = filename.replace('.enc', '')

        guessed_type = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'

        return send_file(
            decrypted_stream,
            as_attachment=True,
            download_name=original_filename,
            mimetype=guessed_type
        )

    except Exception as e:
        flash(f"❌ Decryption failed: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/export_history', methods=['POST'])
def export_history():
    if 'username' not in session:
        return redirect(url_for('login'))

    history = load_encryption_history(session['username'])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Filename', 'Encrypted On', 'Decrypted On'])
    for record in history:
        writer.writerow([record['filename'], record['timestamp'], record['decryption_timestamp'] or '—'])

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=encryption_history.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash("✅ Logged out successfully.", "success")
    return redirect(url_for('login'))

@app.route('/api/encryption_history', methods=['GET'])
def api_encryption_history():
    if 'username' not in session:
        return jsonify({'error': 'Unauthorized access'}), 401

    history = load_encryption_history(session['username'])
    return jsonify(history)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

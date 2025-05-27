import os
from flask import Flask, request, render_template, redirect, url_for, flash, send_file, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import datetime
import io
from cryptography.fernet import InvalidToken

app = Flask(__name__)
app.secret_key = os.urandom(24)
ENCRYPTION_DATA_FILE = 'encryption.data'

# Database initialization
def init_db():
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            encryption_key BLOB NOT NULL,
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            content TEXT,
            timestamp DATETIME,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            offset INTEGER NOT NULL,
            length INTEGER NOT NULL,
            owner_id INTEGER,
            shared_with_id INTEGER,
            file_key BLOB NOT NULL,
            timestamp DATETIME,
            FOREIGN KEY (owner_id) REFERENCES users(id),
            FOREIGN KEY (shared_with_id) REFERENCES users(id)
        )''')
        conn.commit()

# Generate encryption key from password
def generate_encryption_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize keys for storage
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# Deserialize keys from storage
def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

def deserialize_private_key(private_key_bytes):
    return serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

# Encrypt file
def encrypt_file(file_data: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(file_data)

# Decrypt file
def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(encrypted_data)

# Append encrypted data to encryption.data and return offset and length
def store_encrypted_data(encrypted_data: bytes) -> tuple:
    with open(ENCRYPTION_DATA_FILE, 'ab') as f:
        offset = f.tell()
        f.write(encrypted_data)
        length = len(encrypted_data)
    return offset, length

# Read encrypted data from encryption.data using offset and length
def read_encrypted_data(offset: int, length: int) -> bytes:
    with open(ENCRYPTION_DATA_FILE, 'rb') as f:
        f.seek(offset)
        return f.read(length)

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        salt = os.urandom(32)
        encryption_key = generate_encryption_key(password, salt)
        
        # Generate RSA key pair
        private_key, public_key = generate_rsa_key_pair()
        public_key_bytes = serialize_public_key(public_key)
        
        # Encrypt private key with user's encryption key
        f = Fernet(encryption_key)
        private_key_bytes = serialize_private_key(private_key)
        encrypted_private_key = f.encrypt(private_key_bytes)
        
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            try:
                c.execute('INSERT INTO users (username, password, encryption_key, public_key, private_key) VALUES (?, ?, ?, ?, ?)',
                         (username, generate_password_hash(password), salt, public_key_bytes, encrypted_private_key))
                conn.commit()
                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists!')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, password, encryption_key FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            
            if user and check_password_hash(user[1], password):
                session['user_id'] = user[0]
                session['username'] = username
                session['encryption_key'] = generate_encryption_key(password, user[2])
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            flash('Invalid credentials!')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        # Get messages
        c.execute('''SELECT m.content, u.username, m.timestamp 
                    FROM messages m 
                    JOIN users u ON m.sender_id = u.id 
                    WHERE m.receiver_id = ? 
                    ORDER BY m.timestamp DESC''', (session['user_id'],))
        messages = c.fetchall()
        
        # Get shared files
        c.execute('''SELECT f.id, f.filename, u.username, f.timestamp 
                    FROM files f 
                    JOIN users u ON f.owner_id = u.id 
                    WHERE f.shared_with_id = ? 
                    ORDER BY f.timestamp DESC''', (session['user_id'],))
        files = c.fetchall()
        
        # Get users for sharing
        c.execute('SELECT id, username FROM users WHERE id != ?', (session['user_id'],))
        users = c.fetchall()
        
    return render_template('dashboard.html', messages=messages, files=files, users=users)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    receiver_id = request.form['receiver_id']
    content = request.form['content']
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('INSERT INTO messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)',
                 (session['user_id'], receiver_id, content, datetime.datetime.now()))
        conn.commit()
    
    flash('Message sent!')
    return redirect(url_for('dashboard'))

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    file = request.files['file']
    shared_with_id = request.form['shared_with_id']
    
    if file:
        filename = file.filename
        file_data = file.read()
        
        # Generate a file-specific key
        file_key = Fernet.generate_key()
        
        # Encrypt file with file-specific key
        encrypted_data = encrypt_file(file_data, file_key)
        
        # Store encrypted data in encryption.data
        offset, length = store_encrypted_data(encrypted_data)
        
        # Get recipient's public key
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('SELECT public_key FROM users WHERE id = ?', (shared_with_id,))
            recipient = c.fetchone()
            if not recipient:
                flash('Recipient not found!')
                return redirect(url_for('dashboard'))
            public_key_bytes = recipient[0]
        
        # Encrypt file key with recipient's public key
        public_key = deserialize_public_key(public_key_bytes)
        encrypted_file_key = public_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Store file metadata in database
        with sqlite3.connect('database.db') as conn:
            c = conn.cursor()
            c.execute('INSERT INTO files (filename, offset, length, owner_id, shared_with_id, file_key, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)',
                     (filename, offset, length, session['user_id'], shared_with_id, encrypted_file_key, datetime.datetime.now()))
            conn.commit()
        
        flash('File uploaded and shared!')
    
    return redirect(url_for('dashboard'))

@app.route('/download/<int:file_id>')
def download(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    with sqlite3.connect('database.db') as conn:
        c = conn.cursor()
        c.execute('SELECT filename, offset, length, file_key, private_key FROM users u JOIN files f ON u.id = f.shared_with_id WHERE f.id = ? AND f.shared_with_id = ?',
                 (file_id, session['user_id']))
        file = c.fetchone()
        
        if file:
            filename, offset, length, encrypted_file_key, encrypted_private_key = file
            # Read encrypted data from encryption.data
            encrypted_data = read_encrypted_data(offset, length)
            
            try:
                # Decrypt private key with user's encryption key
                f = Fernet(session['encryption_key'])
                private_key_bytes = f.decrypt(encrypted_private_key)
                private_key = deserialize_private_key(private_key_bytes)
                
                # Decrypt file key with private key
                file_key = private_key.decrypt(
                    encrypted_file_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt file with file-specific key
                decrypted_data = decrypt_file(encrypted_data, file_key)
                
                # Return decrypted file as download
                return send_file(
                    io.BytesIO(decrypted_data),
                    download_name=filename,
                    as_attachment=True
                )
            except InvalidToken:
                flash('Decryption failed: Invalid key or corrupted file!')
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash(f'Decryption failed: {str(e)}')
                return redirect(url_for('dashboard'))
        
        flash('File not found or access denied!')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('encryption_key', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
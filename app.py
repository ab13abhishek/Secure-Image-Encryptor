import os
import hashlib
import secrets
import time
import logging
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import safe_join
from flask import Flask, request, jsonify, render_template, send_file, flash, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from Crypto.Cipher import DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import io
import tempfile
import atexit


app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'your-secret-key-change-this-in-production')

# Configure rate limiting (fix: only use keyword arguments)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configuration
UPLOAD_FOLDER = 'uploads'
LOG_FOLDER = 'logs'
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
CLEANUP_INTERVAL_HOURS = 1
FILE_RETENTION_HOURS = 0.5

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)

# Configure logging for cleanup operations
cleanup_logger = logging.getLogger('cleanup')
cleanup_handler = logging.FileHandler(os.path.join(LOG_FOLDER, 'cleanup.log'))
cleanup_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
cleanup_logger.addHandler(cleanup_handler)
cleanup_logger.setLevel(logging.INFO)

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def sanitize_filename(filename):
    """Sanitize filename to prevent directory traversal."""
    return secure_filename(filename)

def generate_key(salt, password='default_password', iterations=100000):
    """Generate encryption key using PBKDF2 with SHA256."""
    return PBKDF2(password, salt, 24, count=iterations, hmac_hash_module=SHA256)  # 24 bytes for 3DES

def pad_data(data):
    """Add PKCS7 padding for DES3."""
    block_size = 8  # DES3 block size
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def unpad_data(data):
    """Remove PKCS7 padding."""
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_image(image_data, salt):
    """Encrypt image data using 3DES with the provided salt."""
    try:
        key = generate_key(salt)
        # Create 3DES cipher
        cipher = DES3.new(key, DES3.MODE_CBC)
        iv = cipher.iv
        # Pad and encrypt data
        padded_data = pad_data(image_data)
        encrypted_data = cipher.encrypt(padded_data)
        # Only store IV + encrypted data (not salt)
        result = iv + encrypted_data
        return result
    except Exception as e:
        app.logger.error(f"Encryption error: {str(e)}")
        raise

def decrypt_image(encrypted_data):
    """Decrypt image data by extracting salt and using 3DES."""
    # Deprecated: decrypt_image now requires salt as argument. Use decrypt_image_with_salt.
    raise NotImplementedError("decrypt_image now requires salt as argument. Use decrypt_image_with_salt.")

def decrypt_image_with_salt(encrypted_data, salt):
    try:
        # Extract IV (first 8 bytes), and encrypted data
        iv = encrypted_data[:8]
        ciphertext = encrypted_data[8:]
        # Generate key using provided salt
        key = generate_key(salt)
        # Create cipher and decrypt
        cipher = DES3.new(key, DES3.MODE_CBC, iv=iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        # Remove padding
        decrypted_data = unpad_data(decrypted_padded)
        return decrypted_data
    except Exception as e:
        app.logger.error(f"Decryption error: {str(e)}")
        raise

def cleanup_old_files():
    """Remove files older than FILE_RETENTION_HOURS from uploads folder."""
    try:
        current_time = time.time()
        cutoff_time = current_time - (FILE_RETENTION_HOURS * 3600)
        removed_count = 0
        
        for filename in os.listdir(UPLOAD_FOLDER):
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                file_mtime = os.path.getmtime(file_path)
                if file_mtime < cutoff_time:
                    os.remove(file_path)
                    removed_count += 1
                    cleanup_logger.info(f"Removed old file: {filename}")
        
        cleanup_logger.info(f"Cleanup completed. Removed {removed_count} files.")
        
    except Exception as e:
        cleanup_logger.error(f"Cleanup error: {str(e)}")

# Schedule cleanup task
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=cleanup_old_files,
    trigger="interval",
    hours=CLEANUP_INTERVAL_HOURS
)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

@app.route('/')
def index():
    """Redirect to encrypt page."""
    return redirect(url_for('encrypt_page'))

@app.route('/encrypt')
def encrypt_page():
    """Render encryption form."""
    return render_template('encrypt.html')

@app.route('/decrypt')
def decrypt_page():
    """Render decryption form."""
    return render_template('decrypt.html')

@app.route('/encrypt_image', methods=['POST'])
@limiter.limit("10 per minute")
def encrypt_image_endpoint():
    """Handle image encryption requests."""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file selected'}), 400
        
        file = request.files['file']
        salt_input = request.form.get('salt', '').strip()
        
        # Validate file
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
            
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only PNG, JPG, and JPEG are allowed.'}), 400
        
        # Check file size
        file_content = file.read()
        if len(file_content) > MAX_FILE_SIZE:
            return jsonify({'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB.'}), 400
        
        # Validate salt
        if not salt_input or len(salt_input.strip()) == 0:
            return jsonify({'error': 'Salt is required for encryption'}), 400
        
        # Generate salt bytes (32 bytes from SHA256)
        salt_bytes = hashlib.sha256(salt_input.encode('utf-8')).digest()
        # Encrypt image (salt not stored in file)
        encrypted_data = encrypt_image(file_content, salt_bytes)
        # Generate unique filename
        timestamp = int(time.time())
        encrypted_filename = f"encrypted_{timestamp}.bin"
        # Save encrypted file temporarily
        encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        return jsonify({
            'success': True,
            'message': 'Image encrypted successfully',
            'download_url': f'/download/{encrypted_filename}',
            'filename': encrypted_filename
        })
        
    except Exception as e:
        app.logger.error(f"Encryption endpoint error: {str(e)}")
        return jsonify({'error': 'Encryption failed. Please try again.'}), 500

@app.route('/decrypt_image', methods=['POST'])
@limiter.limit("10 per minute")
def decrypt_image_endpoint():
    """Handle image decryption requests."""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No encrypted file selected'}), 400
        
        file = request.files['file']
        
        # Validate file
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read encrypted file content
        encrypted_content = file.read()
        if len(encrypted_content) < 8:  # Minimum size for IV
            return jsonify({'error': 'Invalid encrypted file format'}), 400
        # Check file size
        if len(encrypted_content) > MAX_FILE_SIZE * 2:  # Allow some overhead for encrypted files
            return jsonify({'error': 'Encrypted file too large'}), 400
        # Get salt from user input
        salt_input = request.form.get('salt', '').strip()
        if not salt_input or len(salt_input.strip()) == 0:
            return jsonify({'error': 'Salt is required for decryption'}), 400
        salt_bytes = hashlib.sha256(salt_input.encode('utf-8')).digest()
        # Decrypt image
        decrypted_data = decrypt_image_with_salt(encrypted_content, salt_bytes)
        # Generate unique filename for decrypted image
        timestamp = int(time.time())
        decrypted_filename = f"decrypted_{timestamp}.jpg"  # Default to JPG
        # Save decrypted file temporarily
        decrypted_path = os.path.join(UPLOAD_FOLDER, decrypted_filename)
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        return jsonify({
            'success': True,
            'message': 'Image decrypted successfully',
            'download_url': f'/download/{decrypted_filename}',
            'filename': decrypted_filename
        })
        
    except Exception as e:
        app.logger.error(f"Decryption endpoint error: {str(e)}")
        return jsonify({'error': 'Decryption failed. Please check your encrypted file.'}), 500

@app.route('/download/<filename>')
def download_file(filename):
    """Serve file for download."""
    try:
        safe_path = safe_join(UPLOAD_FOLDER, sanitize_filename(filename))
        if safe_path and os.path.exists(safe_path):
            return send_file(safe_path, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        app.logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Download failed'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded."""
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error."""
    return jsonify({'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB.'}), 413

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
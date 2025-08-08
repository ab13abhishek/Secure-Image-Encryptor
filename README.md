# Secure Image Encryptor

A Flask-based web application for secure image encryption and decryption using Triple DES (3DES) encryption with PBKDF2 key derivation and SHA256 hashing.


## Features

- **🔐 Secure Encryption**: Triple DES (3DES) with PBKDF2 key derivation and SHA256 hashing
- **🔑 Salt Management**: Automatic salt embedding and extraction
- **📱 Responsive UI**: Bootstrap-powered interface for all devices
- **🛡️ Security Features**: Rate limiting, file validation, and secure filename handling
- **🧹 Auto Cleanup**: Scheduled file cleanup every hour (24-hour retention)
- **📊 Logging**: Comprehensive cleanup logging for auditing
- **⚡ AJAX**: Smooth file uploads with progress indicators
- **📥 Auto Download**: Automatic file downloads after processing

## Security Specifications

- **Encryption Algorithm**: Triple DES (3DES) in CBC mode
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Hash Function**: SHA256
- **Salt Storage**: Embedded in encrypted file (first 32 bytes)
- **IV Handling**: Randomly generated for each encryption
- **File Validation**: Type and size validation
- **Rate Limiting**: 10 requests per minute per IP
- **Filename Sanitization**: Prevents directory traversal attacks

## Installation

### Prerequisites

- Python 3.8+
- pip (Python package manager)

### Local Setup

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd secure-image-encryptor
   ```

2. **Create virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**:
   ```bash
   # Edit .env file and change the secret key
   FLASK_SECRET_KEY=your-unique-secret-key-here
   FLASK_ENV=development
   ```

5. **Create required directories**:
   ```bash
   mkdir uploads logs
   ```

6. **Run the application**:
   ```bash
   python app.py
   ```

7. **Access the application**:
   Open your browser and navigate to `http://localhost:5000`

## Usage

### Encrypting Images

1. Navigate to the **Encrypt** page
2. Select an image file (PNG, JPG, JPEG - max 5MB)
3. Enter a secure salt (remember this for decryption)
4. Click **"Encrypt Image"**
5. Download the generated `.bin` file automatically

### Decrypting Images

1. Navigate to the **Decrypt** page
2. Select your encrypted `.bin` file
3. Click **"Decrypt Image"** (no salt input needed)
4. Download your original image automatically

## API Endpoints

### POST /encrypt_image
Encrypts an uploaded image file.

**Parameters:**
- `file`: Image file (PNG/JPG/JPEG, max 5MB)
- `salt`: Encryption salt (string)

**Response:**
```json
{
  "success": true,
  "message": "Image encrypted successfully",
  "download_url": "/download/encrypted_1234567890.bin",
  "filename": "encrypted_1234567890.bin"
}
```

### POST /decrypt_image
Decrypts an uploaded encrypted file.

**Parameters:**
- `file`: Encrypted .bin file

**Response:**
```json
{
  "success": true,
  "message": "Image decrypted successfully",
  "download_url": "/download/decrypted_1234567890.jpg",
  "filename": "decrypted_1234567890.jpg"
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions:

1. Check the troubleshooting section
2. Review the logs for error details
3. Create an issue on the repository
4. Provide detailed error messages and steps to reproduce

---

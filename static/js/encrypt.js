document.addEventListener('DOMContentLoaded', function() {
    const encryptForm = document.getElementById('encryptForm');
    const encryptBtn = document.getElementById('encryptBtn');
    const progressContainer = document.getElementById('progressContainer');
    const resultContainer = document.getElementById('resultContainer');
    const imageFile = document.getElementById('imageFile');
    const saltInput = document.getElementById('saltInput');

    // File validation
    imageFile.addEventListener('change', function() {
        const file = this.files[0];
        if (file) {
            // Check file size (5MB limit)
            if (file.size > 5 * 1024 * 1024) {
                showError('File size must be less than 5MB');
                this.value = '';
                return;
            }

            // Check file type
            const allowedTypes = ['image/png', 'image/jpeg', 'image/jpg'];
            if (!allowedTypes.includes(file.type)) {
                showError('Please select a PNG, JPG, or JPEG image');
                this.value = '';
                return;
            }

            showSuccess(`Selected: ${file.name} (${formatFileSize(file.size)})`);
        }
    });

    // Salt validation
    saltInput.addEventListener('input', function() {
        const salt = this.value.trim();
        if (salt.length < 4) {
            this.classList.add('is-invalid');
        } else {
            this.classList.remove('is-invalid');
            this.classList.add('is-valid');
        }
    });

    // Form submission
    encryptForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const file = imageFile.files[0];
        const salt = saltInput.value.trim();

        // Validate inputs
        if (!file) {
            showError('Please select an image file');
            return;
        }

        if (!salt || salt.length < 4) {
            showError('Salt must be at least 4 characters long');
            return;
        }

        // Show loading state
        showLoading();

        const formData = new FormData();
        formData.append('file', file);
        formData.append('salt', salt);

        try {
            const response = await fetch('/encrypt_image', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok && result.success) {
                showSuccessWithDownload(result.message, result.download_url, result.filename);
                encryptForm.reset();
            } else {
                showError(result.error || 'Encryption failed');
            }
        } catch (error) {
            console.error('Error:', error);
            showError('Network error. Please try again.');
        } finally {
            hideLoading();
        }
    });

    function showLoading() {
        encryptBtn.disabled = true;
        encryptBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Encrypting...';
        progressContainer.classList.remove('d-none');
        resultContainer.innerHTML = '';
    }

    function hideLoading() {
        encryptBtn.disabled = false;
        encryptBtn.innerHTML = '<i class="fas fa-lock me-2"></i>Encrypt Image';
        progressContainer.classList.add('d-none');
    }

    function showError(message) {
        resultContainer.innerHTML = `
            <div class="alert alert-danger fade-in" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Error:</strong> ${message}
            </div>
        `;
    }

    function showSuccess(message) {
        resultContainer.innerHTML = `
            <div class="alert alert-success fade-in" role="alert">
                <i class="fas fa-check-circle me-2"></i>
                ${message}
            </div>
        `;
    }

    function showSuccessWithDownload(message, downloadUrl, filename) {
        resultContainer.innerHTML = `
            <div class="alert alert-success fade-in" role="alert">
                <i class="fas fa-check-circle me-2"></i>
                <strong>Success:</strong> ${message}
                <hr>
                <div class="d-grid">
                    <a href="${downloadUrl}" class="download-btn" download="${filename}">
                        <i class="fas fa-download"></i>
                        Download Encrypted File
                    </a>
                </div>
                <small class="text-muted d-block mt-2">
                    <i class="fas fa-info-circle me-1"></i>
                    Save this file safely. You'll need it to decrypt your image.
                </small>
            </div>
        `;

        // Auto-download after a short delay
        setTimeout(() => {
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = filename;
            link.click();
        }, 500);
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Generate random salt button (optional feature)
    const generateSaltBtn = document.createElement('button');
    generateSaltBtn.type = 'button';
    generateSaltBtn.className = 'btn btn-outline-secondary btn-sm';
    generateSaltBtn.innerHTML = '<i class="fas fa-random me-1"></i>Generate';
    generateSaltBtn.addEventListener('click', function() {
        const randomSalt = generateRandomString(16);
        saltInput.value = randomSalt;
        saltInput.classList.remove('is-invalid');
        saltInput.classList.add('is-valid');
    });

    // Add generate button to salt input group
    const saltGroup = document.createElement('div');
    saltGroup.className = 'input-group';
    const saltParent = saltInput.parentNode;
    saltParent.insertBefore(saltGroup, saltInput);
    saltGroup.appendChild(saltInput);
    
    const saltAppend = document.createElement('div');
    saltAppend.className = 'input-group-append';
    saltGroup.appendChild(saltAppend);
    saltAppend.appendChild(generateSaltBtn);

    function generateRandomString(length) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
});
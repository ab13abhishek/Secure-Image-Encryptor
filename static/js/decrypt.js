document.addEventListener('DOMContentLoaded', function() {
    const decryptForm = document.getElementById('decryptForm');
    const decryptBtn = document.getElementById('decryptBtn');
    const progressContainer = document.getElementById('progressContainer');
    const resultContainer = document.getElementById('resultContainer');
    const encryptedFile = document.getElementById('encryptedFile');
    const saltInput = document.getElementById('saltInput');

    // File validation
    encryptedFile.addEventListener('change', function() {
        const file = this.files[0];
        if (file) {
            // Check file size (allow up to 10MB for encrypted files)
            if (file.size > 10 * 1024 * 1024) {
                showError('Encrypted file size must be less than 10MB');
                this.value = '';
                return;
            }

            // Check if file has .bin extension
            if (!file.name.toLowerCase().endsWith('.bin')) {
                showWarning('Selected file doesn\'t have .bin extension. Make sure it\'s an encrypted file.');
            } else {
                showSuccess(`Selected: ${file.name} (${formatFileSize(file.size)})`);
            }
        }
    });

    // Form submission
    decryptForm.addEventListener('submit', async function(e) {
        e.preventDefault();

        const file = encryptedFile.files[0];
        const salt = saltInput.value.trim();

        // Validate input
        if (!file) {
            showError('Please select an encrypted file');
            return;
        }
        if (!salt || salt.length < 4) {
            showError('Salt must be at least 4 characters long');
            saltInput.classList.add('is-invalid');
            return;
        } else {
            saltInput.classList.remove('is-invalid');
            saltInput.classList.add('is-valid');
        }

        // Show loading state
        showLoading();

        const formData = new FormData();
        formData.append('file', file);
        formData.append('salt', salt);

        try {
            const response = await fetch('/decrypt_image', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();

            if (response.ok && result.success) {
                showSuccessWithDownload(result.message, result.download_url, result.filename);
                decryptForm.reset();
                saltInput.classList.remove('is-valid');
            } else {
                showError(result.error || 'Decryption failed');
            }
        } catch (error) {
            console.error('Error:', error);
            showError('Network error. Please try again.');
        } finally {
            hideLoading();
        }
    });

    function showLoading() {
        decryptBtn.disabled = true;
        decryptBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Decrypting...';
        progressContainer.classList.remove('d-none');
        resultContainer.innerHTML = '';
    }

    function hideLoading() {
        decryptBtn.disabled = false;
        decryptBtn.innerHTML = '<i class="fas fa-unlock me-2"></i>Decrypt Image';
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

    function showWarning(message) {
        resultContainer.innerHTML = `
            <div class="alert alert-warning fade-in" role="alert">
                <i class="fas fa-exclamation-triangle me-2"></i>
                <strong>Warning:</strong> ${message}
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
                        Download Decrypted Image
                    </a>
                </div>
                <small class="text-muted d-block mt-2">
                    <i class="fas fa-info-circle me-1"></i>
                    Your image has been successfully decrypted and is ready for download.
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

    // Add drag and drop functionality
    const dropZone = encryptedFile.parentElement;
    
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, unhighlight, false);
    });

    dropZone.addEventListener('drop', handleDrop, false);

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        dropZone.classList.add('bg-light');
    }

    function unhighlight(e) {
        dropZone.classList.remove('bg-light');
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 0) {
            encryptedFile.files = files;
            encryptedFile.dispatchEvent(new Event('change', { bubbles: true }));
        }
    }
});
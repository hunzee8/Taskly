/*global bootstrap*/ // Explicitly declare bootstrap as global for ESLint

document.addEventListener('DOMContentLoaded', function() {
    // ======================
    // Form Handling
    // ======================
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitButton = this.querySelector('button[type="submit"]');
            if (submitButton) {
                // Visual feedback during submission
                submitButton.disabled = true;
                submitButton.innerHTML = `
                    <span class="spinner-border spinner-border-sm" 
                          role="status" 
                          aria-hidden="true"></span> 
                    Processing...
                `;
            }
        });
    });

    // ======================
    // Alert Auto-Dismissal
    // ======================
    const alerts = document.querySelectorAll('.alert');
    if (alerts.length > 0 && typeof bootstrap !== 'undefined') {
        setTimeout(() => {
            alerts.forEach(alert => {
                try {
                    const bsAlert = new bootstrap.Alert(alert);
                    bsAlert.close();
                } catch (error) {
                    console.error('Error closing alert:', error);
                }
            });
        }, 5000); // 5-second timeout
    }

    // ======================
    // Additional Enhancements
    // ======================
    // Password visibility toggle (example enhancement)
    document.querySelectorAll('.password-toggle').forEach(toggle => {
        toggle.addEventListener('click', function() {
            const passwordField = this.previousElementSibling;
            const type = passwordField.type === 'password' ? 'text' : 'password';
            passwordField.type = type;
            this.textContent = type === 'password' ? 'Show' : 'Hide';
        });
    });
});

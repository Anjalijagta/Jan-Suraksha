<?php
require_once __DIR__ . '/config.php';

$err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF Protection
    if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
        $err = 'Invalid security token. Please try again.';
    } else {
        $name = trim($_POST['name'] ?? '');
        $mobile = trim($_POST['mobile'] ?? '');
        $mobile = preg_replace('/\D+/', '', $mobile); // Keep only digits
        $email = trim($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm = $_POST['confirm'] ?? '';

        // Validation
        if (!$name || !preg_match('/^[0-9]{10}$/', $mobile) || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 6 || $password !== $confirm) {
            $err = 'Please fill form correctly: 10-digit mobile, valid email, and matching passwords (min 6 chars).';
        } else {
            // Check for duplicates
            $stmt = $mysqli->prepare('SELECT id FROM users WHERE email = ? OR mobile = ?');
            $stmt->bind_param('ss', $email, $mobile);
            $stmt->execute();
            $stmt->store_result();

            if ($stmt->num_rows > 0) {
                $err = 'Email or mobile already registered.';
            } else {
                // Insert new user
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $ins = $mysqli->prepare('INSERT INTO users (name, mobile, email, password_hash, created_at) VALUES (?, ?, ?, ?, NOW())');
                $ins->bind_param('ssss', $name, $mobile, $email, $hash);

                if ($ins->execute()) {
                    // Session Fixation Protection - Regenerate session ID
                    session_regenerate_id(true);
                    // Regenerate CSRF token after successful registration
                    unset($_SESSION['csrf_token']);
                    header('Location: register-success.php');
                    exit;
                } else {
                    $err = 'Error creating account. Please try again.';
                }
            }
        }
    }
}
?>
<?php include 'header.php'; ?>

<div class="container register-container">
  <div class="row justify-content-center">
    <div class="col-md-6 col-lg-5">
      <div class="auth-card">
        <div class="auth-header">
          <h2><i class="bi bi-shield-check"></i> Create Account</h2>
          <p>Join Jan Suraksha today</p>
        </div>
        <div class="auth-body">
          <?php if($err): ?><div class="alert alert-danger"><?=e($err)?></div><?php endif; ?>
          <form method="post" id="registerForm" novalidate>
            <?php echo csrf_token_field(); ?>
            <div class="mb-3">
              <label class="form-label">Full Name</label>
              <input class="form-control" name="name" type="text" autocomplete="name" placeholder="Enter your full name" required>
              <div class="invalid-feedback">Please enter your full name.</div>
            </div>

            <div class="mb-3">
              <label class="form-label">Mobile Number</label>
              <input class="form-control" name="mobile" type="tel" autocomplete="tel" maxlength="10" placeholder="10 digit mobile number" required>
              <div class="invalid-feedback">Enter a valid 10 digit mobile number.</div>
            </div>

            <div class="mb-3">
              <label class="form-label">Email Address</label>
              <input class="form-control" name="email" type="email" autocomplete="email" placeholder="your.email@example.com" required>
              <div class="invalid-feedback">Enter a valid email address.</div>
            </div>

            <div class="mb-3">
              <label class="form-label">Password</label>
              <div class="input-group">
                <input class="form-control" id="passwordField" name="password" type="password" autocomplete="new-password" placeholder="Create a strong password" minlength="6" required>
                <button class="btn input-group-text" type="button" id="togglePassword">
                  <i class="bi bi-eye" id="toggleIcon"></i>
                </button>
              </div>
              <div class="invalid-feedback">Password must be at least 6 characters.</div>
            </div>

            <div class="mb-3">
              <label class="form-label">Confirm Password</label>
              <div class="input-group">
                <input class="form-control" id="confirmField" name="confirm" type="password" autocomplete="new-password" placeholder="Re-enter your password" required>
                <button class="btn input-group-text" type="button" id="toggleConfirm">
                  <i class="bi bi-eye" id="toggleConfirmIcon"></i>
                </button>
              </div>
              <div class="invalid-feedback">Passwords must match.</div>
            </div>

            <button class="btn btn-primary w-100" type="submit">
              <i class="bi bi-person-plus-fill me-2"></i>Create Account
            </button>
          </form>
          <div class="auth-footer">
            <p class="mb-0">Already have an account? <a href="login.php">Login here</a></p>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('registerForm');
  const nameInput = form.querySelector('input[name="name"]');
  const mobileInput = form.querySelector('input[name="mobile"]');
  const emailInput = form.querySelector('input[name="email"]');
  const passwordInput = document.getElementById('passwordField');
  const confirmInput = document.getElementById('confirmField');

  const togglePasswordBtn = document.getElementById('togglePassword');
  const toggleConfirmBtn = document.getElementById('toggleConfirm');

  // Show / hide password
  togglePasswordBtn.addEventListener('click', function () {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
    document.getElementById('toggleIcon').className =
      isPassword ? 'bi bi-eye-slash' : 'bi bi-eye';
  });

  toggleConfirmBtn.addEventListener('click', function () {
    const isPassword = confirmInput.type === 'password';
    confirmInput.type = isPassword ? 'text' : 'password';
    document.getElementById('toggleConfirmIcon').className =
      isPassword ? 'bi bi-eye-slash' : 'bi bi-eye';
  });

  form.addEventListener('submit', function (e) {
    let hasError = false;

    [nameInput, mobileInput, emailInput, passwordInput, confirmInput].forEach(el => {
      el.classList.remove('is-invalid', 'is-valid');
    });

    // Name required
    if (!nameInput.value.trim()) {
      nameInput.classList.add('is-invalid');
      hasError = true;
    } else {
      nameInput.classList.add('is-valid');
    }

    // Mobile: 10 digits
    const mobileDigits = mobileInput.value.replace(/\D+/g, '');
    if (!/^\d{10}$/.test(mobileDigits)) {
      mobileInput.classList.add('is-invalid');
      hasError = true;
    } else {
      mobileInput.classList.add('is-valid');
    }

    // Email
    if (!emailInput.value.trim() || !emailInput.checkValidity()) {
      emailInput.classList.add('is-invalid');
      hasError = true;
    } else {
      emailInput.classList.add('is-valid');
    }

    // Password length
    if (!passwordInput.value.trim() || passwordInput.value.length < 6) {
      passwordInput.classList.add('is-invalid');
      hasError = true;
    } else {
      passwordInput.classList.add('is-valid');
    }

    // Confirm matches
    if (!confirmInput.value.trim() || confirmInput.value !== passwordInput.value) {
      confirmInput.classList.add('is-invalid');
      hasError = true;
    } else {
      confirmInput.classList.add('is-valid');
    }

    if (hasError) {
      e.preventDefault();
    }
  });
});
</script>
<?php include 'footer.php'; ?>
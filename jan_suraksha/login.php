<?php
require_once __DIR__ . '/config.php';

$err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // CSRF Protection
  if (!validate_csrf_token($_POST['csrf_token'] ?? '')) {
    $err = 'Invalid security token. Please try again.';
  } else {
    $id = trim($_POST['id'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!$id || !$password) {
      $err = 'Please enter both email/mobile and password.';
    } else {
      $stmt = $mysqli->prepare('SELECT id, name, password_hash FROM users WHERE email = ? OR mobile = ?');

      if ($stmt) {
        $stmt->bind_param('ss', $id, $id);

        if ($stmt->execute()) {
          $res = $stmt->get_result();
          $row = $res->fetch_assoc();

          if ($row && password_verify($password, $row['password_hash'])) {
            // Session Fixation Protection - Regenerate session ID
            session_regenerate_id(true);
            $_SESSION['user_id'] = $row['id'];
            $_SESSION['user_name'] = $row['name'];
            // Regenerate CSRF token after successful login
            unset($_SESSION['csrf_token']);
            header('Location: profile.php');
            exit;
          } else {
            $err = 'Invalid email/mobile or password.';
          }
        } else {
          $err = 'Database error. Please try again.';
        }
      } else {
        $err = 'Database error. Please try again.';
      }
    }
  }
  }

?>
<?php include 'header.php'; ?>


  <div class="container login-container">
    <div class="row justify-content-center">
      <div class="col-md-5 col-lg-4">
        <div class="auth-card">
          <div class="auth-header">
            <h2><i class="bi bi-shield-lock-fill"></i> Welcome Back</h2>
            <p>Login to your account</p>
          </div>
          <div class="auth-body">
            <?php if ($err): ?><div class="alert alert-danger"><?= e($err) ?></div><?php endif; ?>
            <form method="post" id="loginForm" novalidate>
              <?php echo csrf_token_field(); ?>
              <div class="mb-3">
                <label class="form-label">Email or Mobile Number</label>
                <input class="form-control" name="id" type="text" autocomplete="username" placeholder="Enter email or mobile number" required>
                <div class="invalid-feedback">Please enter your email or mobile number.</div>
              </div>

              <div class="mb-3">
                <label class="form-label">Password</label>
                <div class="input-group">
                  <input class="form-control" id="passwordField" name="password" type="password" autocomplete="current-password" placeholder="Enter your password" required minlength="6">
                  <button class="btn input-group-text" type="button" id="togglePassword">
                    <i class="bi bi-eye" id="toggleIcon"></i>
                  </button>
                </div>
                <div class="invalid-feedback">Password must be at least 6 characters.</div>
              </div>

              <button class="btn btn-primary w-100" type="submit">
                <i class="bi bi-box-arrow-in-right me-2"></i>Login
              </button>
            </form>
            <div class="auth-footer">
              <p class="mb-0">Don't have an account? <a href="register.php">Register here</a></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <script>
    document.addEventListener('DOMContentLoaded', function() {
      const form = document.getElementById('loginForm');
      const idInput = form.querySelector('input[name="id"]');
      const passwordInput = document.getElementById('passwordField');
      const togglePasswordBtn = document.getElementById('togglePassword');

      togglePasswordBtn.addEventListener('click', function() {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        const icon = document.getElementById('toggleIcon');
        icon.className = isPassword ? 'bi bi-eye-slash' : 'bi bi-eye';
      });

      // Simple client-side validation
      form.addEventListener('submit', function(e) {
        let hasError = false;

        // reset states
        [idInput, passwordInput].forEach(el => {
          el.classList.remove('is-invalid', 'is-valid');
        });

        // validate id (required)
        if (!idInput.value.trim()) {
          idInput.classList.add('is-invalid');
          hasError = true;
        } else {
          idInput.classList.add('is-valid');
        }

        // validate password (required, min length 6)
        if (!passwordInput.value.trim() || passwordInput.value.length < 6) {
          passwordInput.classList.add('is-invalid');
          hasError = true;
        } else {
          passwordInput.classList.add('is-valid');
        }

        if (hasError) {
          e.preventDefault();
        }
      });
    });
  </script>
<?php include 'footer.php'; ?>
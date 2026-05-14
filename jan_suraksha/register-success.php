<?php
require_once __DIR__ . '/config.php';
?>
<?php include 'header.php'; ?>

<div class="success-card">
  <div class="success-header">
    <div class="success-icon">
      <i class="bi bi-check-circle-fill"></i>
    </div>
    <h2>Account Created!</h2>
    <p>Your registration is complete</p>
  </div>
  <div class="success-body">
    <p><strong>Welcome to Jan Suraksha!</strong></p>
    <p>Your account has been successfully created. You can now login with your credentials to access your profile and file complaints.</p>
    <a href="login.php" class="btn btn-primary">
      <i class="bi bi-box-arrow-in-right me-2"></i>Go to Login
    </a>
  </div>
</div>
<?php include 'footer.php'; ?>
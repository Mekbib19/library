<?php
// Add this at the top of the file (after the opening PHP tag)
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;

class Auth {
    private $conn;
    private $config;
    private $tfa;

    public function __construct($conn) {
        $this->conn = $conn;
        
        // Load configuration
        $this->loadConfig();
        
        // Secure session configuration
        $this->configureSession();
        
        // Start and secure session
        $this->startSecureSession();
        
        // Initialize database
        $this->initializeDatabase();
        
        // Initialize TFA if needed
        $this->initializeMfa();
    }

    /* ============================================================
       MFA INITIALIZATION
       ============================================================ */
    private function initializeMfa() {
        if ($this->getSetting('enable_2fa') === '1') {
            try {
                // Update database schema for MFA backup codes
                $this->conn->query("
                    ALTER TABLE users 
                    ADD COLUMN IF NOT EXISTS mfa_backup_codes TEXT NULL
                ");
            } catch (Exception $e) {
                $this->logEvent('error', "Failed to update MFA schema: " . $e->getMessage());
            }
        }
    }

    /* ============================================================
       TOTP MFA IMPLEMENTATION (Google Authenticator compatible)
       ============================================================ */
    private function getTfaInstance() {
        if ($this->tfa === null) {
            try {
                $this->tfa = new TwoFactorAuth(
                    'YourAppName',           // Change to your site name
                    6,                       // 6-digit codes
                    30,                      // 30-second period
                    'sha1',                  // Algorithm
                    new BaconQrCodeProvider()
                );
            } catch (Exception $e) {
                $this->logEvent('error', "Failed to initialize TFA: " . $e->getMessage());
                throw new Exception("MFA initialization failed");
            }
        }
        return $this->tfa;
    }

    /**
     * Generate a new TOTP secret and QR code for user setup
     */
    public function generateMfaSecret($userId) {
        // Check if MFA is enabled globally
        if ($this->getSetting('enable_2fa') !== '1') {
            return ['success' => false, 'error' => 'MFA is not enabled on this system'];
        }

        $user = $this->getUserById($userId);
        if (!$user) {
            return ['success' => false, 'error' => 'User not found'];
        }

        try {
            $tfa = $this->getTfaInstance();
            $secret = $tfa->createSecret(160); // 160 bits = very secure

            // Generate QR code as data URI
            $label = rawurlencode($user['user_name'] . '@YourAppName');
            $qrCode = $tfa->getQRCodeImageAsDataUri($label, $secret);

            // Temporarily store secret in session until confirmed
            $_SESSION['pending_mfa_secret'] = $secret;
            $_SESSION['pending_mfa_user_id'] = $userId;
            $_SESSION['pending_mfa_expires'] = time() + 600; // 10 minutes expiry

            $this->auditLog($userId, 'MFA_SETUP_STARTED', 'Started MFA setup process');

            return [
                'success' => true,
                'secret' => $secret,
                'qrCode' => $qrCode
            ];
        } catch (Exception $e) {
            $this->logEvent('error', "Failed to generate MFA secret: " . $e->getMessage());
            return ['success' => false, 'error' => 'Failed to generate MFA setup'];
        }
    }

    /**
     * Confirm and enable MFA after user scans QR and enters valid code
     */
    public function enableMfa($userId, $code, $currentPassword = null) {
        // Verify user is logged in and matches the session
        if (!$this->isLoggedIn() || $_SESSION['USER_ID'] != $userId) {
            return ['success' => false, 'error' => 'Authentication required'];
        }

        // Check if MFA is enabled globally
        if ($this->getSetting('enable_2fa') !== '1') {
            return ['success' => false, 'error' => 'MFA is not enabled on this system'];
        }

        // Verify current password if provided (optional but recommended)
        if ($currentPassword !== null) {
            $user = $this->getUserById($userId);
            if (!$user || !password_verify($currentPassword, $user['password'])) {
                $this->auditLog($userId, 'MFA_SETUP_FAILED', 'Invalid current password provided');
                return ['success' => false, 'error' => 'Current password is incorrect'];
            }
        }

        // Check session data
        if (!isset($_SESSION['pending_mfa_secret']) || 
            $_SESSION['pending_mfa_user_id'] != $userId ||
            time() > $_SESSION['pending_mfa_expires']) {
            return ['success' => false, 'error' => 'MFA setup session expired. Please start again.'];
        }

        $secret = $_SESSION['pending_mfa_secret'];
        $code = trim($code);

        try {
            $tfa = $this->getTfaInstance();
            
            // Verify with 1 period tolerance (30 seconds before/after)
            if (!$tfa->verifyCode($secret, $code, 1)) {
                $this->auditLog($userId, 'MFA_SETUP_FAILED', 'Invalid verification code entered');
                return ['success' => false, 'error' => 'Invalid verification code'];
            }

            // Generate 10 one-time backup codes (store as hashed values)
            $backupCodes = [];
            $hashedBackupCodes = [];
            for ($i = 0; $i < 10; $i++) {
                $code = strtoupper(substr(bin2hex(random_bytes(5)), 0, 8)); // 8-char readable codes
                $backupCodes[] = $code;
                $hashedBackupCodes[] = password_hash($code, PASSWORD_DEFAULT);
            }

            // Store hashed backup codes
            $backupJson = json_encode($hashedBackupCodes);

            $stmt = $this->conn->prepare("
                UPDATE users 
                SET mfa_secret = ?, mfa_enabled = 1, mfa_backup_codes = ?
                WHERE id = ?
            ");
            $stmt->bind_param("ssi", $secret, $backupJson, $userId);
            $success = $stmt->execute();
            $stmt->close();

            if ($success) {
                // Clear pending session
                unset($_SESSION['pending_mfa_secret'], 
                      $_SESSION['pending_mfa_user_id'], 
                      $_SESSION['pending_mfa_expires']);

                $this->auditLog($userId, 'MFA_ENABLED', 'Two-factor authentication enabled');
                $this->logEvent('info', "MFA enabled for user ID: $userId");

                return [
                    'success' => true,
                    'backup_codes' => $backupCodes, // Return plain codes only once
                    'message' => 'MFA enabled successfully. Save your backup codes in a safe place.'
                ];
            }

            return ['success' => false, 'error' => 'Failed to enable MFA'];

        } catch (Exception $e) {
            $this->logEvent('error', "MFA enable failed: " . $e->getMessage());
            return ['success' => false, 'error' => 'Failed to enable MFA'];
        }
    }

    /**
     * Disable MFA (requires current password)
     */
    public function disableMfa($userId, $currentPassword) {
        if (!$this->isLoggedIn() || $_SESSION['USER_ID'] != $userId) {
            return ['success' => false, 'error' => 'Authentication required'];
        }

        // Verify current password
        $user = $this->getUserById($userId);
        if (!$user || !password_verify($currentPassword, $user['password'])) {
            $this->auditLog($userId, 'MFA_DISABLE_FAILED', 'Invalid password provided');
            return ['success' => false, 'error' => 'Current password is incorrect'];
        }

        $stmt = $this->conn->prepare("
            UPDATE users 
            SET mfa_secret = NULL, mfa_enabled = 0, mfa_backup_codes = NULL
            WHERE id = ?
        ");
        $stmt->bind_param("i", $userId);
        $success = $stmt->execute();
        $stmt->close();

        if ($success) {
            $this->auditLog($userId, 'MFA_DISABLED', 'Two-factor authentication disabled');
            $this->logEvent('info', "MFA disabled for user ID: $userId");
            return ['success' => true, 'message' => 'MFA disabled successfully'];
        }

        return ['success' => false, 'error' => 'Failed to disable MFA'];
    }

    /**
     * Verify TOTP code during login (or use backup code)
     */
    private function verifyMfaCode($secret, $code) {
        if ($secret === null) return false;

        $code = trim($code);
        $userId = $_SESSION['USER_ID'] ?? null;
        if (!$userId) return false;

        try {
            $tfa = $this->getTfaInstance();
            
            // First try normal TOTP
            if ($tfa->verifyCode($secret, $code, 2)) { // 2 = 60-second tolerance
                return true;
            }

            // Then try backup codes (one-time use)
            $stmt = $this->conn->prepare("SELECT mfa_backup_codes FROM users WHERE id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result();
            $row = $result->fetch_assoc();
            $stmt->close();

            if (!$row || empty($row['mfa_backup_codes'])) return false;

            $hashedBackupCodes = json_decode($row['mfa_backup_codes'], true);
            if (!is_array($hashedBackupCodes)) return false;

            // Check each backup code
            foreach ($hashedBackupCodes as $index => $hashedCode) {
                if (password_verify($code, $hashedCode)) {
                    // Remove used backup code
                    unset($hashedBackupCodes[$index]);
                    $newCodes = json_encode(array_values($hashedBackupCodes));

                    $stmt = $this->conn->prepare("UPDATE users SET mfa_backup_codes = ? WHERE id = ?");
                    $stmt->bind_param("si", $newCodes, $userId);
                    $stmt->execute();
                    $stmt->close();

                    $this->auditLog($userId, 'MFA_BACKUP_CODE_USED', "Backup code used for login");
                    $this->logEvent('info', "Backup code used for user ID: $userId");
                    
                    return true;
                }
            }

            return false;

        } catch (Exception $e) {
            $this->logEvent('error', "MFA verification failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Regenerate backup codes (requires current password)
     */
    public function regenerateBackupCodes($userId, $currentPassword) {
        if (!$this->isLoggedIn() || $_SESSION['USER_ID'] != $userId) {
            return ['success' => false, 'error' => 'Authentication required'];
        }

        // Verify current password
        $user = $this->getUserById($userId);
        if (!$user || !password_verify($currentPassword, $user['password'])) {
            $this->auditLog($userId, 'MFA_BACKUP_REGEN_FAILED', 'Invalid password provided');
            return ['success' => false, 'error' => 'Current password is incorrect'];
        }

        // Check if MFA is enabled
        if (!$user['mfa_enabled']) {
            return ['success' => false, 'error' => 'MFA is not enabled for this account'];
        }

        // Generate new backup codes
        $backupCodes = [];
        $hashedBackupCodes = [];
        for ($i = 0; $i < 10; $i++) {
            $code = strtoupper(substr(bin2hex(random_bytes(5)), 0, 8));
            $backupCodes[] = $code;
            $hashedBackupCodes[] = password_hash($code, PASSWORD_DEFAULT);
        }

        $json = json_encode($hashedBackupCodes);
        $stmt = $this->conn->prepare("UPDATE users SET mfa_backup_codes = ? WHERE id = ?");
        $stmt->bind_param("si", $json, $userId);
        $stmt->execute();
        $stmt->close();

        $this->auditLog($userId, 'MFA_BACKUP_CODES_REGENERATED', 'Backup codes regenerated');
        $this->logEvent('info', "Backup codes regenerated for user ID: $userId");

        return [
            'success' => true,
            'backup_codes' => $backupCodes,
            'message' => 'Backup codes regenerated. Save these new codes immediately.'
        ];
    }

    /**
     * Get MFA status for a user
     */
    public function getMfaStatus($userId) {
        $stmt = $this->conn->prepare("
            SELECT mfa_enabled, 
                   CASE WHEN mfa_backup_codes IS NOT NULL 
                        THEN JSON_LENGTH(mfa_backup_codes) 
                        ELSE 0 
                   END as backup_codes_remaining
            FROM users 
            WHERE id = ?
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();

        if (!$row) {
            return ['success' => false, 'error' => 'User not found'];
        }

        return [
            'success' => true,
            'mfa_enabled' => (bool)$row['mfa_enabled'],
            'backup_codes_remaining' => (int)$row['backup_codes_remaining'],
            'system_enabled' => $this->getSetting('enable_2fa') === '1'
        ];
    }

    /* ============================================================
       UPDATE THE login() METHOD TO USE NEW MFA VERIFICATION
       ============================================================ */
    // Inside the login() method, replace the MFA block with:

    /* ============================================================
       ENHANCED LOGIN WITH BRUTE FORCE PROTECTION
       ============================================================ */
    public function login($username, $password, $remember = false, $mfaCode = null) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // Audit log
        $this->auditLog(null, 'LOGIN_ATTEMPT', "Login attempt for $username from $ip", $ip, $userAgent);

        // Get security settings
        $maxAttempts = (int)$this->getSetting('max_attempts') ?: 5;
        $lockMinutes = (int)$this->getSetting('lock_minutes') ?: 5;
        $baseDelay = (int)$this->getSetting('login_delay_base') ?: 2;
        $maxDelay = (int)$this->getSetting('max_login_delay') ?: 64;

        // Check IP blocking
        if ($this->isIpBlocked($ip)) {
            $this->logEvent('warn', "Login blocked - IP is blocked: $ip");
            return ['success' => false, 'error' => 'Access denied'];
        }

        // Check if user exists and isn't locked
        $user = $this->getUserByUsername($username);
        if (!$user) {
            // Simulate delay even for non-existent users
            $this->simulateDelay(2);
            $this->increaseAttempts($username, $ip, $userAgent);
            $this->logEvent('info', "Failed login - unknown user: $username from $ip");
            return ['success' => false, 'error' => 'Invalid credentials'];
        }

        // Check if account is locked
        if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
            $remaining = strtotime($user['locked_until']) - time();
            $this->logEvent('warn', "Login blocked - account locked: $username", [
                'locked_until' => $user['locked_until'],
                'remaining_seconds' => $remaining
            ]);
            return ['success' => false, 'error' => 'Account is locked. Please try again later.'];
        }

        // Apply progressive delay based on failed attempts
        $this->applyLoginDelay($user['failed_attempts'], $baseDelay, $maxDelay);

        // Verify password
        if (!password_verify($password, $user['password'])) {
            $this->handleFailedLogin($user, $ip, $userAgent, $maxAttempts, $lockMinutes);
            return ['success' => false, 'error' => 'Invalid credentials'];
        }

        // Check password expiry
        $passwordExpiryDays = (int)$this->getSetting('password_expiry_days') ?: 90;
        if ($passwordExpiryDays > 0) {
            $passwordAge = time() - strtotime($user['password_changed']);
            if ($passwordAge > ($passwordExpiryDays * 86400)) {
                return [
                    'success' => false, 
                    'error' => 'Password has expired',
                    'password_expired' => true,
                    'user_id' => $user['id']
                ];
            }
        }

        // Check MFA if enabled
        if ($user['mfa_enabled'] && $this->getSetting('enable_2fa') === '1') {
            if (!$mfaCode) {
                // Store partial login info for MFA step
                $_SESSION['pending_mfa_user_id'] = $user['id'];
                $_SESSION['pending_mfa_expires'] = time() + 300; // 5 minutes for MFA
                
                return [
                    'success' => false,
                    'error' => 'MFA required',
                    'mfa_required' => true,
                    'user_id' => $user['id'],
                    'partial_token' => bin2hex(random_bytes(16))
                ];
            }
            
            // Verify MFA code (includes backup code check)
            if (!$this->verifyMfaCode($user['mfa_secret'], $mfaCode)) {
                $this->handleFailedLogin($user, $ip, $userAgent, $maxAttempts, $lockMinutes);
                return ['success' => false, 'error' => 'Invalid MFA code or backup code'];
            }
            
            // Clear pending MFA session
            unset($_SESSION['pending_mfa_user_id'], $_SESSION['pending_mfa_expires']);
        }

        // Login successful
        return $this->handleSuccessfulLogin($user, $ip, $userAgent, $remember);
    }

    /* ============================================================
       ADDITIONAL MFA-RELATED METHODS
       ============================================================ */
    
    /**
     * Verify MFA code for an already logged-in user (e.g., for sensitive operations)
     */
    public function verifyMfaForOperation($userId, $code) {
        if (!$this->isLoggedIn() || $_SESSION['USER_ID'] != $userId) {
            return ['success' => false, 'error' => 'Authentication required'];
        }

        $user = $this->getUserById($userId);
        if (!$user || !$user['mfa_enabled']) {
            return ['success' => false, 'error' => 'MFA not enabled for this account'];
        }

        if ($this->verifyMfaCode($user['mfa_secret'], $code)) {
            // Set temporary MFA verification in session (e.g., for 10 minutes)
            $_SESSION['mfa_verified'] = time() + 600;
            $this->auditLog($userId, 'MFA_OPERATION_VERIFIED', 'MFA verified for sensitive operation');
            return ['success' => true];
        }

        $this->auditLog($userId, 'MFA_OPERATION_FAILED', 'MFA verification failed for operation');
        return ['success' => false, 'error' => 'Invalid MFA code'];
    }

    /**
     * Check if MFA verification is still valid for sensitive operations
     */
    public function isMfaVerified($userId) {
        return isset($_SESSION['mfa_verified']) && 
               $_SESSION['mfa_verified'] > time() &&
               $_SESSION['USER_ID'] == $userId;
    }

    /* ============================================================
       UPDATE THE changePassword METHOD TO REQUIRE MFA
       ============================================================ */
    public function changePassword($userId, $currentPassword, $newPassword, $mfaCode = null) {
        // Get user
        $stmt = $this->conn->prepare("SELECT password, mfa_enabled, mfa_secret FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        if (!$user) {
            return ['success' => false, 'error' => 'User not found'];
        }
        
        // Verify current password
        if (!password_verify($currentPassword, $user['password'])) {
            $this->auditLog($userId, 'PASSWORD_CHANGE_FAILED', 'Current password incorrect');
            return ['success' => false, 'error' => 'Current password is incorrect'];
        }

        // If MFA is enabled, require MFA code for password change
        if ($user['mfa_enabled'] && $this->getSetting('enable_2fa') === '1') {
            if (!$mfaCode) {
                return [
                    'success' => false,
                    'error' => 'MFA required for password change',
                    'mfa_required' => true
                ];
            }
            
            if (!$this->verifyMfaCode($user['mfa_secret'], $mfaCode)) {
                $this->auditLog($userId, 'PASSWORD_CHANGE_MFA_FAILED', 'Invalid MFA code for password change');
                return ['success' => false, 'error' => 'Invalid MFA code'];
            }
        }
        
        // Check new password strength
        $passwordCheck = $this->validatePasswordStrength($newPassword);
        if (!$passwordCheck['valid']) {
            return ['success' => false, 'error' => $passwordCheck['error']];
        }
        
        // Check password history
        $newHash = password_hash($newPassword, PASSWORD_DEFAULT, ['cost' => 12]);
        if ($this->isPasswordInHistory($userId, $newPassword)) {
            return ['success' => false, 'error' => 'Password was used recently. Choose a different password.'];
        }
        
        // Update password
        $stmt = $this->conn->prepare("
            UPDATE users 
            SET password = ?, password_changed = NOW() 
            WHERE id = ?
        ");
        $stmt->bind_param("si", $newHash, $userId);
        
        if ($stmt->execute()) {
            // Add to history
            $this->addToPasswordHistory($userId, $newHash);
            
            // Audit log
            $this->auditLog($userId, 'PASSWORD_CHANGED', 'Password changed successfully');
            
            $this->logEvent('info', "Password changed for user ID: $userId");
            
            $stmt->close();
            return ['success' => true];
        }
        
        $stmt->close();
        return ['success' => false, 'error' => 'Failed to change password'];
    }

    // ... rest of your existing code remains the same ...
}
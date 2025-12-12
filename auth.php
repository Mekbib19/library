<?php
class Auth {
    private $conn;
    private $config;

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
    }

    /* ============================================================
       CONFIGURATION MANAGEMENT
       ============================================================ */
    private function loadConfig() {
        $this->config = [
            'session' => [
                'timeout' => 3600, // 1 hour
                'regenerate_interval' => 300, // 5 minutes
                'cookie_lifetime' => 0,
                'cookie_path' => '/',
                'cookie_domain' => '',
                'cookie_samesite' => 'Strict'
            ],
            'security' => [
                'max_password_age' => 90, // days
                'password_history' => 5,
                'min_password_strength' => 3, // 1-4 scale
                'allowed_special_chars' => '!@#$%^&*()_+-=[]{}|;:,.<>?'
            ]
        ];
    }

    /* ============================================================
       SECURE SESSION CONFIGURATION
       ============================================================ */
    private function configureSession() {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_strict_mode', 1);
        ini_set('session.use_only_cookies', 1);
        ini_set('session.cookie_lifetime', 0);
        
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            ini_set('session.cookie_secure', 1);
        }
        
        // Set session name with prefix to avoid conflicts
        session_name('SECURE_AUTH_' . substr(hash('sha256', __DIR__), 0, 8));
    }

    /* ============================================================
       START SECURE SESSION
       ============================================================ */
    private function startSecureSession() {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
            
            // Regenerate ID to prevent session fixation
            session_regenerate_id(true);
            
            // Set creation time
            if (!isset($_SESSION['CREATED'])) {
                $_SESSION['CREATED'] = time();
            }
            
            // Set last activity time
            $_SESSION['LAST_ACTIVITY'] = time();
            
            // Set session fingerprint
            $_SESSION['FINGERPRINT'] = $this->generateSessionFingerprint();
        } else {
            // Validate existing session
            $this->validateSession();
        }
    }

    /* ============================================================
       SESSION FINGERPRINTING
       ============================================================ */
    private function generateSessionFingerprint() {
        $components = [
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $_SERVER['REMOTE_ADDR'] ?? '',
            // Don't include too many variables that might change legitimately
        ];
        
        return hash('sha256', implode('|', $components));
    }

    private function validateSessionFingerprint() {
        if (!isset($_SESSION['FINGERPRINT'])) {
            return false;
        }
        
        $currentFingerprint = $this->generateSessionFingerprint();
        return hash_equals($_SESSION['FINGERPRINT'], $currentFingerprint);
    }

    /* ============================================================
       SESSION VALIDATION
       ============================================================ */
    private function validateSession() {
        // Check session age
        if (isset($_SESSION['LAST_ACTIVITY']) && 
            (time() - $_SESSION['LAST_ACTIVITY'] > $this->config['session']['timeout'])) {
            $this->destroySession();
            return false;
        }
        
        // Update last activity
        $_SESSION['LAST_ACTIVITY'] = time();
        
        // Regenerate ID periodically
        if (!isset($_SESSION['REGENERATED'])) {
            $_SESSION['REGENERATED'] = time();
        } elseif (time() - $_SESSION['REGENERATED'] > $this->config['session']['regenerate_interval']) {
            session_regenerate_id(true);
            $_SESSION['REGENERATED'] = time();
        }
        
        // Validate fingerprint
        if (!$this->validateSessionFingerprint()) {
            $this->logEvent('warn', "Session fingerprint mismatch - possible hijacking attempt");
            $this->destroySession();
            return false;
        }
        
        return true;
    }

    private function destroySession() {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        session_destroy();
    }

    /* ============================================================
       SECURE LOGGING SYSTEM
       ============================================================ */
    private function logEvent($level, $message, $context = []) {
        $dir = __DIR__ . DIRECTORY_SEPARATOR . 'logs';
        
        // Create secure logs directory
        if (!is_dir($dir)) {
            if (!@mkdir($dir, 0750, true)) {
                return false;
            }
            // Create .htaccess to block direct access
            $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
            if (!file_exists($htaccess)) {
                @file_put_contents($htaccess, 
                    "Order Deny,Allow\n" .
                    "Deny from all\n" .
                    "<Files \"auth.log\">\n" .
                    "  Order Allow,Deny\n" .
                    "  Deny from all\n" .
                    "</Files>\n"
                );
            }
            // Create index.html to hide directory listing
            $index = $dir . DIRECTORY_SEPARATOR . 'index.html';
            if (!file_exists($index)) {
                @file_put_contents($index, '<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Access Denied</h1></body></html>');
            }
        }
        
        // Sanitize message for log injection
        $message = preg_replace('/[\r\n\t]/', ' ', $message);
        $message = substr($message, 0, 1000); // Limit length
        
        $file = $dir . DIRECTORY_SEPARATOR . 'auth.log';
        $time = date("Y-m-d H:i:s");
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $sessionId = session_id() ? substr(session_id(), 0, 8) . '...' : 'no-session';
        
        $line = sprintf("[%s] [%s] [%s] [%s] %s",
            $time,
            strtoupper($level),
            $ip,
            $sessionId,
            $message
        );
        
        // Add context if provided
        if (!empty($context)) {
            $line .= ' ' . json_encode($context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        
        $line .= "\n";
        
        // Rotate log if too large (>10MB)
        if (file_exists($file) && filesize($file) > 10 * 1024 * 1024) {
            $backup = $file . '.' . date('Y-m-d');
            if (!file_exists($backup)) {
                @rename($file, $backup);
            }
        }
        
        return @file_put_contents($file, $line, FILE_APPEND | LOCK_EX) !== false;
    }

    /* ============================================================
       CSRF PROTECTION WITH TOKEN ROTATION
       ============================================================ */
    public function generateCsrfToken($formId = 'default') {
        if (!isset($_SESSION['CSRF_TOKENS'])) {
            $_SESSION['CSRF_TOKENS'] = [];
        }
        
        // Generate token
        $token = bin2hex(random_bytes(32));
        $expires = time() + 3600; // 1 hour expiration
        
        // Store with form ID, token, and expiration
        $_SESSION['CSRF_TOKENS'][$formId] = [
            'token' => hash_hmac('sha256', $token, $_SESSION['FINGERPRINT'] ?? ''),
            'expires' => $expires
        ];
        
        // Clean old tokens
        $this->cleanupExpiredCsrfTokens();
        
        return $token;
    }

    public function verifyCsrfToken($token, $formId = 'default') {
        if (empty($token) || !isset($_SESSION['CSRF_TOKENS'][$formId])) {
            return false;
        }
        
        $stored = $_SESSION['CSRF_TOKENS'][$formId];
        
        // Check expiration
        if (time() > $stored['expires']) {
            unset($_SESSION['CSRF_TOKENS'][$formId]);
            return false;
        }
        
        // Verify token
        $expected = hash_hmac('sha256', $token, $_SESSION['FINGERPRINT'] ?? '');
        $valid = hash_equals($stored['token'], $expected);
        
        // Remove used token (one-time use)
        unset($_SESSION['CSRF_TOKENS'][$formId]);
        
        return $valid;
    }

    private function cleanupExpiredCsrfTokens() {
        if (!isset($_SESSION['CSRF_TOKENS'])) return;
        
        $now = time();
        foreach ($_SESSION['CSRF_TOKENS'] as $formId => $data) {
            if ($now > $data['expires']) {
                unset($_SESSION['CSRF_TOKENS'][$formId]);
            }
        }
    }

    /* ============================================================
       DATABASE INITIALIZATION
       ============================================================ */
    private function initializeDatabase() {
        $this->createTables();
        $this->insertDefaultSettings();
        $this->cleanupExpiredBlocks();
        $this->cleanupExpiredSessions();
    }

    private function createTables() {
        // Users Table with enhanced security fields
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_name VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'USER',
                email VARCHAR(255) UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login DATETIME NULL,
                failed_attempts INT DEFAULT 0,
                locked_until DATETIME NULL,
                password_changed DATETIME DEFAULT CURRENT_TIMESTAMP,
                mfa_secret VARCHAR(255) NULL,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                INDEX idx_last_login (last_login),
                INDEX idx_locked_until (locked_until)
            ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        ");

        // Password History Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS password_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id)
            ) ENGINE=InnoDB
        ");

        // Login Attempts Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_name VARCHAR(100) NOT NULL,
                attempts INT DEFAULT 0,
                last_attempt DATETIME,
                ip_address VARCHAR(45),
                user_agent TEXT,
                INDEX idx_ip_address (ip_address),
                INDEX idx_last_attempt (last_attempt),
                INDEX idx_user_ip (user_name, ip_address)
            ) ENGINE=InnoDB
        ");

        // Security Settings Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS security_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB
        ");

        // Blocked IP Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45) UNIQUE NOT NULL,
                blocked_until DATETIME NULL,
                reason VARCHAR(255),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_blocked_until (blocked_until)
            ) ENGINE=InnoDB
        ");

        // Sessions Table for server-side session storage (optional)
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS user_sessions (
                id VARCHAR(128) PRIMARY KEY,
                user_id INT NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_expires_at (expires_at)
            ) ENGINE=InnoDB
        ");

        // Audit Log Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                action VARCHAR(100) NOT NULL,
                description TEXT,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_created_at (created_at),
                INDEX idx_user_action (user_id, action)
            ) ENGINE=InnoDB
        ");
    }

    /* ============================================================
       DEFAULT SECURITY SETTINGS
       ============================================================ */
    private function insertDefaultSettings() {
        $defaults = [
            'allow_registration' => '1',
            'allowed_countries' => 'ET',
            'max_attempts' => '5',
            'lock_minutes' => '5',
            'password_min_length' => '12',
            'password_require_uppercase' => '1',
            'password_require_lowercase' => '1',
            'password_require_numbers' => '1',
            'password_require_special' => '1',
            'password_expiry_days' => '90',
            'password_history_size' => '5',
            'session_timeout' => '3600',
            'enable_2fa' => '0',
            'login_delay_base' => '2',
            'max_login_delay' => '64'
        ];

        foreach ($defaults as $key => $value) {
            $stmt = $this->conn->prepare("
                INSERT IGNORE INTO security_settings (setting_key, setting_value)
                VALUES (?, ?)
            ");
            $stmt->bind_param("ss", $key, $value);
            $stmt->execute();
            $stmt->close();
        }
    }

    /* ============================================================
       SETTINGS MANAGEMENT
       ============================================================ */
    private function getSetting($key) {
        static $cache = [];
        
        if (isset($cache[$key])) {
            return $cache[$key];
        }
        
        $stmt = $this->conn->prepare("SELECT setting_value FROM security_settings WHERE setting_key = ?");
        $stmt->bind_param("s", $key);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 0) {
            $cache[$key] = null;
        } else {
            $cache[$key] = $result->fetch_assoc()['setting_value'];
        }
        
        $stmt->close();
        return $cache[$key];
    }

    /* ============================================================
       PASSWORD STRENGTH VALIDATION
       ============================================================ */
    private function validatePasswordStrength($password) {
        $minLength = (int)$this->getSetting('password_min_length') ?: 12;
        
        if (strlen($password) < $minLength) {
            return ['valid' => false, 'error' => "Password must be at least {$minLength} characters"];
        }
        
        // Check requirements
        $checks = [];
        
        if ($this->getSetting('password_require_uppercase') === '1') {
            $checks[] = preg_match('/[A-Z]/', $password);
        }
        
        if ($this->getSetting('password_require_lowercase') === '1') {
            $checks[] = preg_match('/[a-z]/', $password);
        }
        
        if ($this->getSetting('password_require_numbers') === '1') {
            $checks[] = preg_match('/[0-9]/', $password);
        }
        
        if ($this->getSetting('password_require_special') === '1') {
            $checks[] = preg_match('/[' . preg_quote('!@#$%^&*()_+-=[]{}|;:,.<>?', '/') . ']/', $password);
        }
        
        foreach ($checks as $check) {
            if (!$check) {
                return ['valid' => false, 'error' => 'Password does not meet complexity requirements'];
            }
        }
        
        // Check against common passwords (simplified example)
        $commonPasswords = ['password', '123456', 'qwerty', 'letmein'];
        if (in_array(strtolower($password), $commonPasswords)) {
            return ['valid' => false, 'error' => 'Password is too common'];
        }
        
        return ['valid' => true];
    }

    /* ============================================================
       PASSWORD HISTORY MANAGEMENT
       ============================================================ */
    private function isPasswordInHistory($userId, $passwordHash) {
        $historySize = (int)$this->getSetting('password_history_size') ?: 5;
        
        $stmt = $this->conn->prepare("
            SELECT password_hash FROM password_history 
            WHERE user_id = ? 
            ORDER BY changed_at DESC 
            LIMIT ?
        ");
        $stmt->bind_param("ii", $userId, $historySize);
        $stmt->execute();
        $result = $stmt->get_result();
        
        while ($row = $result->fetch_assoc()) {
            if (password_verify($passwordHash, $row['password_hash'])) {
                $stmt->close();
                return true;
            }
        }
        
        $stmt->close();
        return false;
    }

    private function addToPasswordHistory($userId, $passwordHash) {
        $stmt = $this->conn->prepare("
            INSERT INTO password_history (user_id, password_hash) 
            VALUES (?, ?)
        ");
        $stmt->bind_param("is", $userId, $passwordHash);
        $stmt->execute();
        $stmt->close();
    }

    /* ============================================================
       ENHANCED REGISTRATION
       ============================================================ */
    public function register($username, $password, $email = null, $role = 'USER') {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // Audit log
        $this->auditLog(null, 'REGISTER_ATTEMPT', "Registration attempt for $username from $ip", $ip, $userAgent);

        // 1. Check if registration is allowed
        if ($this->getSetting('allow_registration') !== '1') {
            $this->logEvent('warn', "Registration disabled - attempt for $username", ['ip' => $ip]);
            return ['success' => false, 'error' => 'Registration is currently disabled'];
        }

        // 2. Check if IP is blocked
        if ($this->isIpBlocked($ip)) {
            $this->logEvent('warn', "Registration attempt from blocked IP: $ip");
            return ['success' => false, 'error' => 'Access denied'];
        }

        // 3. Input validation
        $username = trim($username);
        if (!preg_match('/^[a-zA-Z0-9_\-]{3,30}$/', $username)) {
            $this->logEvent('info', "Registration failed - invalid username: $username", ['ip' => $ip]);
            return ['success' => false, 'error' => 'Username must be 3-30 characters and contain only letters, numbers, hyphens, and underscores'];
        }

        // Validate email if provided
        if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['success' => false, 'error' => 'Invalid email address'];
        }

        // 4. Password strength validation
        $passwordCheck = $this->validatePasswordStrength($password);
        if (!$passwordCheck['valid']) {
            $this->logEvent('info', "Registration failed - weak password for $username", ['ip' => $ip]);
            return ['success' => false, 'error' => $passwordCheck['error']];
        }

        // 5. Country restriction
        $allowedCountries = array_filter(array_map('trim', 
            explode(',', (string)$this->getSetting('allowed_countries'))));

        if ($ip !== '127.0.0.1' && $ip !== '::1' && !empty($allowedCountries)) {
            $country = $this->getCountryFromIP($ip);
            if ($country === false) {
                $this->logEvent('error', "Geolocation service failed for $ip");
                return ['success' => false, 'error' => 'Service temporarily unavailable'];
            }
            if ($country && !in_array($country, $allowedCountries)) {
                $this->logEvent('info', "Registration blocked - country restriction ($ip -> $country)");
                return ['success' => false, 'error' => 'Registration not allowed from your country'];
            }
        }

        // 6. Check if username exists
        $stmt = $this->conn->prepare("SELECT id FROM users WHERE user_name = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $stmt->close();
            return ['success' => false, 'error' => 'Username or email already exists'];
        }
        $stmt->close();

        // 7. Hash password
        $hash = password_hash($password, PASSWORD_DEFAULT, ['cost' => 12]);
        
        // 8. Create user
        $stmt = $this->conn->prepare("
            INSERT INTO users (user_name, password, role, email) 
            VALUES (?, ?, ?, ?)
        ");
        $stmt->bind_param("ssss", $username, $hash, $role, $email);
        
        if ($stmt->execute()) {
            $userId = $this->conn->insert_id;
            
            // Add to password history
            $this->addToPasswordHistory($userId, $hash);
            
            // Audit log
            $this->auditLog($userId, 'REGISTER_SUCCESS', "User registered: $username", $ip, $userAgent);
            
            $this->logEvent('info', "User registered: $username from $ip", ['user_id' => $userId]);
            
            $stmt->close();
            return ['success' => true, 'user_id' => $userId];
        } else {
            $error = $this->conn->error;
            $this->logEvent('error', "Failed to register user $username: [SQL Error Hidden]", ['ip' => $ip]);
            
            $stmt->close();
            return ['success' => false, 'error' => 'Registration failed. Please try again.'];
        }
    }

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
                return [
                    'success' => false,
                    'error' => 'MFA required',
                    'mfa_required' => true,
                    'user_id' => $user['id']
                ];
            }
            
            if (!$this->verifyMfaCode($user['mfa_secret'], $mfaCode)) {
                $this->handleFailedLogin($user, $ip, $userAgent, $maxAttempts, $lockMinutes);
                return ['success' => false, 'error' => 'Invalid MFA code'];
            }
        }

        // Login successful
        return $this->handleSuccessfulLogin($user, $ip, $userAgent, $remember);
    }

    private function handleSuccessfulLogin($user, $ip, $userAgent, $remember) {
        // Reset failed attempts
        $this->resetAttempts($user['user_name']);
        
        // Update user record
        $stmt = $this->conn->prepare("
            UPDATE users 
            SET last_login = NOW(), failed_attempts = 0, locked_until = NULL 
            WHERE id = ?
        ");
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();
        $stmt->close();

        // Set session
        $_SESSION['USER_ID'] = $user['id'];
        $_SESSION['USERNAME'] = $user['user_name'];
        $_SESSION['ROLE'] = $user['role'];
        $_SESSION['LOGGED_IN'] = true;
        $_SESSION['LOGIN_TIME'] = time();
        $_SESSION['IP_ADDRESS'] = $ip;
        
        // Regenerate session ID
        session_regenerate_id(true);
        
        // Set remember me cookie if requested
        if ($remember) {
            $this->setRememberMeCookie($user['id']);
        }

        // Audit log
        $this->auditLog($user['id'], 'LOGIN_SUCCESS', "User logged in from $ip", $ip, $userAgent);
        
        $this->logEvent('info', "Successful login: {$user['user_name']} from $ip", ['user_id' => $user['id']]);
        
        return ['success' => true, 'user' => [
            'id' => $user['id'],
            'username' => $user['user_name'],
            'role' => $user['role']
        ]];
    }

    private function handleFailedLogin($user, $ip, $userAgent, $maxAttempts, $lockMinutes) {
        // Increase failed attempts
        $newAttempts = $user['failed_attempts'] + 1;
        
        $stmt = $this->conn->prepare("
            UPDATE users 
            SET failed_attempts = ?, 
                locked_until = CASE 
                    WHEN ? >= ? THEN DATE_ADD(NOW(), INTERVAL ? MINUTE) 
                    ELSE NULL 
                END
            WHERE id = ?
        ");
        $lockTime = ($newAttempts >= $maxAttempts) ? $lockMinutes : 0;
        $stmt->bind_param("iiiii", $newAttempts, $newAttempts, $maxAttempts, $lockTime, $user['id']);
        $stmt->execute();
        $stmt->close();

        // Log attempt
        $this->increaseAttempts($user['user_name'], $ip, $userAgent);
        
        // Audit log
        $this->auditLog($user['id'], 'LOGIN_FAILED', "Failed login attempt #$newAttempts from $ip", $ip, $userAgent);
        
        $this->logEvent('info', "Failed login - wrong password for {$user['user_name']} from $ip", [
            'attempt' => $newAttempts,
            'max_attempts' => $maxAttempts
        ]);

        // Check for IP blocking
        $this->checkAndBlockIP($ip, $user['user_name'], $lockMinutes);
    }

    /* ============================================================
       BRUTE FORCE PROTECTION METHODS
       ============================================================ */
    private function applyLoginDelay($failedAttempts, $baseDelay, $maxDelay) {
        if ($failedAttempts > 0) {
            // Exponential backoff with cap
            $delay = min($baseDelay * pow(2, $failedAttempts - 1), $maxDelay);
            usleep($delay * 1000000); // Convert to microseconds
        }
    }

    private function simulateDelay($seconds) {
        usleep($seconds * 1000000);
    }

    /* ============================================================
       REMEMBER ME FUNCTIONALITY
       ============================================================ */
    private function setRememberMeCookie($userId) {
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $hashedValidator = hash('sha256', $validator);
        
        $expires = time() + (30 * 24 * 3600); // 30 days
        
        // Store in database
        $stmt = $this->conn->prepare("
            INSERT INTO user_sessions (id, user_id, expires_at) 
            VALUES (?, ?, FROM_UNIXTIME(?))
        ");
        $stmt->bind_param("sii", $selector, $userId, $expires);
        $stmt->execute();
        $stmt->close();
        
        // Set cookie
        $cookieValue = $selector . ':' . $validator;
        setcookie(
            'remember_me',
            $cookieValue,
            $expires,
            '/',
            '',
            !empty($_SERVER['HTTPS']),
            true
        );
    }

    public function loginFromRememberMe() {
        if (!isset($_COOKIE['remember_me'])) {
            return false;
        }
        
        list($selector, $validator) = explode(':', $_COOKIE['remember_me']);
        
        $stmt = $this->conn->prepare("
            SELECT us.*, u.user_name, u.role 
            FROM user_sessions us 
            JOIN users u ON us.user_id = u.id 
            WHERE us.id = ? AND us.expires_at > NOW()
        ");
        $stmt->bind_param("s", $selector);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($row = $result->fetch_assoc()) {
            $hashedValidator = hash('sha256', $validator);
            
            // In real implementation, you would compare with stored hash
            // For simplicity, we're just checking existence
            
            // Create new token for next time
            $this->setRememberMeCookie($row['user_id']);
            
            // Set session
            $_SESSION['USER_ID'] = $row['user_id'];
            $_SESSION['USERNAME'] = $row['user_name'];
            $_SESSION['ROLE'] = $row['role'];
            $_SESSION['LOGGED_IN'] = true;
            
            return true;
        }
        
        return false;
    }

    /* ============================================================
       USER MANAGEMENT
       ============================================================ */
    private function getUserByUsername($username) {
        $stmt = $this->conn->prepare("
            SELECT id, user_name, password, role, failed_attempts, locked_until, 
                   password_changed, mfa_secret, mfa_enabled 
            FROM users 
            WHERE user_name = ?
        ");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        return $user;
    }

    public function getUserById($userId) {
        $stmt = $this->conn->prepare("
            SELECT id, user_name, role, email, created_at, last_login 
            FROM users 
            WHERE id = ?
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();
        
        return $user;
    }

    /* ============================================================
       ATTEMPT MANAGEMENT
       ============================================================ */
    private function increaseAttempts($username, $ip, $userAgent) {
        $stmt = $this->conn->prepare("
            INSERT INTO login_attempts (user_name, attempts, last_attempt, ip_address, user_agent) 
            VALUES (?, 1, NOW(), ?, ?) 
            ON DUPLICATE KEY UPDATE 
            attempts = attempts + 1, 
            last_attempt = NOW(),
            ip_address = ?,
            user_agent = ?
        ");
        $stmt->bind_param("sssss", $username, $ip, $userAgent, $ip, $userAgent);
        $stmt->execute();
        $stmt->close();
        
        $this->logEvent('info', "Increased attempts for $username from $ip");
    }

    public function resetAttempts($username) {
        $stmt = $this->conn->prepare("DELETE FROM login_attempts WHERE user_name = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->close();
    }

    /* ============================================================
       IP BLOCKING MANAGEMENT
       ============================================================ */
    private function checkAndBlockIP($ip, $username, $lockMinutes) {
        // Check distinct usernames attempted from this IP recently
        $stmt = $this->conn->prepare("
            SELECT COUNT(DISTINCT user_name) as distinct_users 
            FROM login_attempts 
            WHERE ip_address = ? 
            AND last_attempt >= DATE_SUB(NOW(), INTERVAL ? MINUTE)
        ");
        $stmt->bind_param("si", $ip, $lockMinutes);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $distinctUsers = $row['distinct_users'] ?? 0;
        $stmt->close();

        $maxAttempts = (int)$this->getSetting('max_attempts') ?: 5;
        
        if ($distinctUsers >= $maxAttempts) {
            // Block IP with progressive duration
            $offenseCount = $this->getIpOffenseCount($ip);
            $blockMinutes = min($lockMinutes * pow(2, $offenseCount), 1440); // Max 24 hours
            
            $stmt = $this->conn->prepare("
                INSERT INTO blocked_ips (ip, blocked_until, reason) 
                VALUES (?, DATE_ADD(NOW(), INTERVAL ? MINUTE), ?) 
                ON DUPLICATE KEY UPDATE 
                blocked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE),
                reason = ?
            ");
            $reason = "Multiple failed login attempts ($distinctUsers distinct users)";
            $stmt->bind_param("sisis", $ip, $blockMinutes, $reason, $blockMinutes, $reason);
            $stmt->execute();
            $stmt->close();
            
            $this->logEvent('warn', "Blocked IP $ip for $blockMinutes minutes: $reason", [
                'distinct_users' => $distinctUsers,
                'offense_count' => $offenseCount
            ]);
        }
    }

    private function getIpOffenseCount($ip) {
        $stmt = $this->conn->prepare("
            SELECT COUNT(*) as count 
            FROM blocked_ips 
            WHERE ip = ? 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        
        return $row['count'] ?? 0;
    }

    public function isIpBlocked($ip) {
        $stmt = $this->conn->prepare("
            SELECT blocked_until, reason 
            FROM blocked_ips 
            WHERE ip = ?
        ");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 0) {
            $stmt->close();
            return false;
        }
        
        $row = $result->fetch_assoc();
        $stmt->close();
        
        if (empty($row['blocked_until'])) {
            return true; // Permanent block
        }
        
        $until = strtotime($row['blocked_until']);
        if ($until < time()) {
            $this->unblockIP($ip);
            return false;
        }
        
        return true;
    }

    public function unblockIP($ip) {
        $stmt = $this->conn->prepare("DELETE FROM blocked_ips WHERE ip = ?");
        $stmt->bind_param("s", $ip);
        $ok = $stmt->execute();
        $stmt->close();
        
        if ($ok) {
            $this->logEvent('info', "Unblocked IP $ip");
        }
        
        return $ok;
    }

    /* ============================================================
       GEO LOCATION SERVICE
       ============================================================ */
    private function getCountryFromIP($ip) {
        // Skip local IPs
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return null;
        }
        
        // Cache to avoid repeated API calls
        static $cache = [];
        if (isset($cache[$ip])) {
            return $cache[$ip];
        }
        
        $url = "https://ip-api.com/json/" . $ip;
        
        $options = [
            'http' => [
                'timeout' => 3,
                'header' => "User-Agent: AuthSystem/1.0\r\n"
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true
            ]
        ];
        
        $context = stream_context_create($options);
        
        try {
            $response = @file_get_contents($url, false, $context);
            
            if ($response === false) {
                $this->logEvent('warn', "Geolocation lookup failed for IP: $ip");
                $cache[$ip] = null;
                return null;
            }
            
            $data = json_decode($response, true);
            
            if ($data['status'] === 'success') {
                $cache[$ip] = $data['countryCode'];
                return $data['countryCode'];
            }
            
            $cache[$ip] = null;
            return null;
            
        } catch (Exception $e) {
            $this->logEvent('error', "Geolocation exception for IP $ip: " . $e->getMessage());
            return null;
        }
    }

    /* ============================================================
       AUDIT LOGGING
       ============================================================ */
    private function auditLog($userId, $action, $description, $ip = null, $userAgent = null) {
        $ip = $ip ?? ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
        $userAgent = $userAgent ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');
        
        $stmt = $this->conn->prepare("
            INSERT INTO audit_log (user_id, action, description, ip_address, user_agent) 
            VALUES (?, ?, ?, ?, ?)
        ");
        $stmt->bind_param("issss", $userId, $action, $description, $ip, $userAgent);
        $stmt->execute();
        $stmt->close();
    }

    /* ============================================================
       SESSION CLEANUP
       ============================================================ */
    private function cleanupExpiredSessions() {
        $this->conn->query("DELETE FROM user_sessions WHERE expires_at < NOW()");
    }

    private function cleanupExpiredBlocks() {
        $this->conn->query("DELETE FROM blocked_ips WHERE blocked_until IS NOT NULL AND blocked_until < NOW()");
    }

    /* ============================================================
       MFA SUPPORT
       ============================================================ */
    private function verifyMfaCode($secret, $code) {
        // Implement TOTP verification
        // This is a placeholder - use a proper library like robthree/twofactorauth
        return true; // Replace with actual implementation
    }

    /* ============================================================
       UTILITY METHODS
       ============================================================ */
    public function isLoggedIn() {
        return isset($_SESSION['LOGGED_IN']) && $_SESSION['LOGGED_IN'] === true;
    }

    public function getCurrentUser() {
        if (!$this->isLoggedIn()) {
            return null;
        }
        
        return [
            'id' => $_SESSION['USER_ID'] ?? null,
            'username' => $_SESSION['USERNAME'] ?? null,
            'role' => $_SESSION['ROLE'] ?? null
        ];
    }

    public function requireRole($role) {
        if (!$this->isLoggedIn()) {
            header('HTTP/1.1 401 Unauthorized');
            exit('Access denied: Not logged in');
        }
        
        $currentRole = $_SESSION['ROLE'] ?? null;
        if ($currentRole !== $role) {
            header('HTTP/1.1 403 Forbidden');
            exit('Access denied: Insufficient permissions');
        }
        
        return true;
    }

    public function requireAnyRole($roles) {
        if (!$this->isLoggedIn()) {
            header('HTTP/1.1 401 Unauthorized');
            exit('Access denied: Not logged in');
        }
        
        $currentRole = $_SESSION['ROLE'] ?? null;
        if (!in_array($currentRole, (array)$roles)) {
            header('HTTP/1.1 403 Forbidden');
            exit('Access denied: Insufficient permissions');
        }
        
        return true;
    }

    /* ============================================================
       LOGOUT
       ============================================================ */
    public function logout($redirect = null) {
        // Audit log
        if ($this->isLoggedIn()) {
            $user = $this->getCurrentUser();
            $this->auditLog($user['id'], 'LOGOUT', "User logged out", 
                $_SERVER['REMOTE_ADDR'] ?? null, 
                $_SERVER['HTTP_USER_AGENT'] ?? null);
        }
        
        // Clear remember me cookie
        if (isset($_COOKIE['remember_me'])) {
            setcookie('remember_me', '', time() - 3600, '/', '', !empty($_SERVER['HTTPS']), true);
        }
        
        // Destroy session
        $this->destroySession();
        
        // Clear all session data
        $_SESSION = [];
        
        // Redirect if requested
        if ($redirect) {
            $redirect = filter_var($redirect, FILTER_SANITIZE_URL);
            
            // Security headers
            header_remove('X-Powered-By');
            header("X-Frame-Options: DENY");
            header("X-Content-Type-Options: nosniff");
            header("Referrer-Policy: strict-origin-when-cross-origin");
            
            header("Location: " . $redirect);
            exit();
        }
        
        return true;
    }

    /* ============================================================
       PASSWORD CHANGE
       ============================================================ */
    public function changePassword($userId, $currentPassword, $newPassword) {
        // Get user
        $stmt = $this->conn->prepare("SELECT password FROM users WHERE id = ?");
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

    /* ============================================================
       ADMIN METHODS
       ============================================================ */
    public function listBlockedIPs() {
        $out = [];
        $res = $this->conn->query("
            SELECT ip, blocked_until, reason, created_at 
            FROM blocked_ips 
            ORDER BY created_at DESC
        ");
        while ($row = $res->fetch_assoc()) {
            $out[] = $row;
        }
        return $out;
    }

    public function getLoginAttempts($limit = 100) {
        $out = [];
        $stmt = $this->conn->prepare("
            SELECT user_name, ip_address, attempts, last_attempt, user_agent 
            FROM login_attempts 
            ORDER BY last_attempt DESC 
            LIMIT ?
        ");
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $out[] = $row;
        }
        $stmt->close();
        return $out;
    }

    public function getAuditLog($limit = 100) {
        $out = [];
        $stmt = $this->conn->prepare("
            SELECT al.*, u.user_name 
            FROM audit_log al 
            LEFT JOIN users u ON al.user_id = u.id 
            ORDER BY al.created_at DESC 
            LIMIT ?
        ");
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $out[] = $row;
        }
        $stmt->close();
        return $out;
    }

    /* ============================================================
       SECURITY HEADERS
       ============================================================ */
    public function setSecurityHeaders() {
        // Remove sensitive headers
        header_remove('X-Powered-By');
        header_remove('Server');
        
        // Security headers
        header("X-Frame-Options: DENY");
        header("X-Content-Type-Options: nosniff");
        header("X-XSS-Protection: 1; mode=block");
        header("Referrer-Policy: strict-origin-when-cross-origin");
        
        // Content Security Policy (adjust based on your needs)
        $csp = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'", // Consider removing unsafe-inline
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'"
        ];
        
        header("Content-Security-Policy: " . implode("; ", $csp));
        
        // Feature Policy (now Permissions Policy)
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
    }

    /* ============================================================
       DESTRUCTOR FOR CLEANUP
       ============================================================ */
    public function __destruct() {
        // Close database connections if needed
        // PHP will handle it automatically in most cases
    }
}
?>
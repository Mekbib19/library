<?php
class Auth {
    private $conn;

    public function __construct($conn) {
        $this->conn = $conn;

        ini_set('session.cookie_httponly', 1);
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            ini_set('session.cookie_secure', 1);
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $this->createTables();
        $this->insertDefaultSettings();
        $this->cleanupExpiredBlocks();
    }

    /* ============================================================
       SIMPLE FILE LOGGING
       ============================================================ */
    private function logEvent($level, $message) {
        $dir = __DIR__ . DIRECTORY_SEPARATOR . 'logs';
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $file = $dir . DIRECTORY_SEPARATOR . 'auth.log';
        $time = date("Y-m-d H:i:s");
        $line = sprintf("[%s] %s: %s\n", $time, strtoupper($level), $message);
        @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
    }

    /* ============================================================
       CSRF HELPERS
       ============================================================ */
    public function generateCsrfToken() {
        if (empty($_SESSION['CSRF_TOKEN'])) {
            $_SESSION['CSRF_TOKEN'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['CSRF_TOKEN'];
    }

    public function verifyCsrfToken($token) {
        if (empty($token) || empty($_SESSION['CSRF_TOKEN'])) return false;
        $valid = hash_equals($_SESSION['CSRF_TOKEN'], $token);
        if ($valid) unset($_SESSION['CSRF_TOKEN']);
        return $valid;
    }

    /* ============================================================
       CREATE REQUIRED TABLES
       ============================================================ */
    private function createTables() {

        // Users Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_name VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL DEFAULT 'USER'
            ) ENGINE=InnoDB
        ");

        // Login Attempts Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_name VARCHAR(100) NOT NULL,
                attempts INT DEFAULT 0,
                last_attempt DATETIME,
                ip_address VARCHAR(45)
            ) ENGINE=InnoDB
        ");

        // Security Settings Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS security_settings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                setting_key VARCHAR(100) UNIQUE NOT NULL,
                setting_value TEXT NOT NULL
            ) ENGINE=InnoDB
        ");

        // Blocked IP Table
        $this->conn->query("
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45) UNIQUE NOT NULL,
                blocked_until DATETIME NULL
            ) ENGINE=InnoDB
        ");
    }

        // Ensure column exists on older schemas
        $this->conn->query("ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS blocked_until DATETIME NULL");

    /* ============================================================
       DEFAULT SECURITY SETTINGS
       ============================================================ */
    private function insertDefaultSettings() {
        $defaults = [
            'allow_registration' => '1',
            'allowed_countries' => 'ET',
            'max_attempts' => '5',
            'lock_minutes' => '5'
        ];

        foreach ($defaults as $key => $value) {
            $stmt = $this->conn->prepare("
                INSERT IGNORE INTO security_settings (setting_key, setting_value)
                VALUES (?, ?)
            ");
            $stmt->bind_param("ss", $key, $value);
            $stmt->execute();
        }
    }

    /* ============================================================
       READ SETTINGS
       ============================================================ */
    private function getSetting($key) {
        $stmt = $this->conn->prepare("SELECT setting_value FROM security_settings WHERE setting_key=?");
        $stmt->bind_param("s", $key);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows == 0) return null;
        return $result->fetch_assoc()['setting_value'];
    }

    /* ============================================================
       REGISTER USER
       ============================================================ */
    public function register($username, $password, $role = 'USER') {
        $ip = $_SERVER['REMOTE_ADDR'];

        // 1. Check if registration is allowed
        if ($this->getSetting('allow_registration') !== '1') {
            return false;
        }

        // 2. Check if IP is blocked (respect expiry)
        if ($this->isIpBlocked($ip)) {
            $this->logEvent('warn', "Registration attempt from blocked IP: $ip");
            return false;
        }

        // 2b. Basic input validation
        $username = trim($username);
        if (!preg_match('/^[a-zA-Z0-9_\-]{3,30}$/', $username)) {
            $this->logEvent('info', "Registration failed - invalid username: $username");
            return false;
        }
        if (strlen($password) < 8) {
            $this->logEvent('info', "Registration failed - weak password for user: $username");
            return false;
        }
        // 3. Country restriction
        $allowedCountries = array_filter(array_map('trim', explode(',', (string)$this->getSetting('allowed_countries'))));

        // Skip localhost
        if ($ip !== '127.0.0.1' && $ip !== '::1' && !empty($allowedCountries)) {
            $response = @file_get_contents("https://ip-api.com/json/" . $ip);
            if ($response) {
                $data = json_decode($response, true);
                $country = $data['countryCode'] ?? null;
                if (!$country || !in_array($country, $allowedCountries)) {
                    $this->logEvent('info', "Registration blocked - country restriction ($ip -> $country)");
                    return false;
                }
            } else {
                // Allow registration if geo lookup fails, but log for review
                $this->logEvent('warn', "Geolocation lookup failed for IP $ip during registration; allowing by fallback");
            }
        }

        // 4. Register user
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->conn->prepare("INSERT INTO users (user_name, password, role) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $hash, $role);
        $ok = $stmt->execute();
        if ($ok) {
            $this->logEvent('info', "User registered: $username from $ip");
        } else {
            $this->logEvent('error', "Failed to register user $username: " . $this->conn->error);
        }
        return $ok;
    }

    /* ============================================================
       LOGIN USER
       ============================================================ */
    public function login($username, $password) {
        $ip = $_SERVER['REMOTE_ADDR'];

        // Read attempt limits from DB
        $maxAttempts = (int)$this->getSetting('max_attempts');
        $lockMinutes = (int)$this->getSetting('lock_minutes');

        // Check attempts
        $attempts = $this->getAttempts($username);

        // Also check attempts by IP
        $ipAttempts = $this->getAttemptsByIP($ip);

        if ($ipAttempts['attempts'] >= $maxAttempts) {
            $lastTime = strtotime($ipAttempts['last_attempt']);
            $diff = time() - $lastTime;
            if ($diff < ($lockMinutes * 60)) {
                $this->logEvent('warn', "Login blocked by IP rate limit: $ip");
                return false;
            }
        }

        if ($attempts['attempts'] >= $maxAttempts) {
            $lastTime = strtotime($attempts['last_attempt']);
            $diff = time() - $lastTime;

            if ($diff < ($lockMinutes * 60)) {
                return false;
            } else {
                $this->resetAttempts($username);
            }
        }

        // Validate user
        $stmt = $this->conn->prepare("SELECT * FROM users WHERE user_name=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $res = $stmt->get_result();

        if ($res->num_rows == 0) {
            $this->increaseAttempts($username, $ip);
            $this->logEvent('info', "Failed login - unknown user: $username from $ip");
            return false;
        }

        $user = $res->fetch_assoc();

        if (password_verify($password, $user['password'])) {
            $_SESSION['ROLE'] = $user['role'];
            $_SESSION['ID'] = $user['id'];
            session_regenerate_id(true);
            $this->resetAttempts($username);
            $this->logEvent('info', "Successful login: $username from $ip");
            return true;
        }

        $this->increaseAttempts($username, $ip);
        $this->logEvent('info', "Failed login - wrong password for $username from $ip");
        return false;
    }

    /* ============================================================
       ATTEMPT CONTROLS
       ============================================================ */
    private function getAttempts($username) {
        $stmt = $this->conn->prepare("SELECT * FROM login_attempts WHERE user_name=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $res = $stmt->get_result();

        if ($res->num_rows == 0)
            return ['attempts' => 0, 'last_attempt' => null];

        return $res->fetch_assoc();
    }

    private function getAttemptsByIP($ip) {
        $stmt = $this->conn->prepare("SELECT SUM(attempts) as attempts, MAX(last_attempt) as last_attempt FROM login_attempts WHERE ip_address = ?");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res->num_rows == 0) return ['attempts' => 0, 'last_attempt' => null];
        $row = $res->fetch_assoc();
        return ['attempts' => (int)$row['attempts'], 'last_attempt' => $row['last_attempt']];
    }

    /* ============================================================
       BLOCKED IP HELPERS
       ============================================================ */
    public function isIpBlocked($ip) {
        $stmt = $this->conn->prepare("SELECT blocked_until FROM blocked_ips WHERE ip = ?");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res->num_rows == 0) return false;
        $row = $res->fetch_assoc();
        if (empty($row['blocked_until'])) return true; // permanent block
        $until = strtotime($row['blocked_until']);
        if ($until === false) return true;
        if ($until < time()) {
            // expired - clean up
            $this->unblockIP($ip);
            return false;
        }
        return true;
    }

    public function listBlockedIPs() {
        $out = [];
        $res = $this->conn->query("SELECT ip, blocked_until FROM blocked_ips");
        while ($row = $res->fetch_assoc()) $out[] = $row;
        return $out;
    }

    public function unblockIP($ip) {
        $stmt = $this->conn->prepare("DELETE FROM blocked_ips WHERE ip = ?");
        $stmt->bind_param("s", $ip);
        $ok = $stmt->execute();
        if ($ok) $this->logEvent('info', "Unblocked IP $ip");
        return $ok;
    }

    private function cleanupExpiredBlocks() {
        $this->conn->query("DELETE FROM blocked_ips WHERE blocked_until IS NOT NULL AND blocked_until < NOW()");
    }

    private function increaseAttempts($username, $ip) {
        $attempts = $this->getAttempts($username);
        $now = date("Y-m-d H:i:s");

        if ($attempts['attempts'] == 0) {
            $stmt = $this->conn->prepare("
                INSERT INTO login_attempts (user_name, attempts, last_attempt, ip_address)
                VALUES (?, 1, ?, ?)
            ");
            $stmt->bind_param("sss", $username, $now, $ip);
        } else {
            $newCount = $attempts['attempts'] + 1;
            $stmt = $this->conn->prepare("
                UPDATE login_attempts SET attempts=?, last_attempt=?, ip_address=?
                WHERE user_name=?
            ");
            $stmt->bind_param("isss", $newCount, $now, $ip, $username);
        }

        $stmt->execute();
        $this->logEvent('info', "Increased attempts for $username (now " . ($attempts['attempts'] + 1) . ") from $ip");

        // If an IP has tried logging in with multiple different usernames repeatedly,
        // block the IP by inserting into `blocked_ips` when distinct username count
        // within the lock window reaches the configured max attempts.
        $lockMinutes = (int)$this->getSetting('lock_minutes');
        $maxAttempts = (int)$this->getSetting('max_attempts');

        if ($lockMinutes > 0 && $maxAttempts > 0) {
            $stmt2 = $this->conn->prepare("SELECT COUNT(DISTINCT user_name) as cnt FROM login_attempts WHERE ip_address = ? AND last_attempt >= DATE_SUB(NOW(), INTERVAL ? MINUTE)");
            $stmt2->bind_param("si", $ip, $lockMinutes);
            $stmt2->execute();
            $res2 = $stmt2->get_result();
            $distinct = 0;
            if ($row = $res2->fetch_assoc()) {
                $distinct = (int)$row['cnt'];
            }

                if ($distinct >= $maxAttempts) {
                    $stmt3 = $this->conn->prepare("INSERT INTO blocked_ips (ip, blocked_until) VALUES (?, DATE_ADD(NOW(), INTERVAL ? MINUTE)) ON DUPLICATE KEY UPDATE blocked_until = DATE_ADD(NOW(), INTERVAL ? MINUTE)");
                    $stmt3->bind_param("sii", $ip, $lockMinutes, $lockMinutes);
                    $stmt3->execute();
                    $this->logEvent('warn', "Blocked IP $ip due to $distinct distinct failed username attempts for $lockMinutes minutes");
                }
        }
    }

    public function resetAttempts($username) {
        $stmt = $this->conn->prepare("DELETE FROM login_attempts WHERE user_name=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
    }

    /* ============================================================
       LOGOUT
       ============================================================ */
    public function logout($hader) {
        session_unset();
        session_destroy();
        header("Location:$hader");
        exit();
    }
}
?>

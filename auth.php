<?php
class Auth {
    private $conn;

    public function __construct($conn) {
        $this->conn = $conn;

        ini_set('session.cookie_httponly', 1);
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
            ini_set('session.cookie_secure', 1);
        }

        session_start();

        $this->createTables();
        $this->insertDefaultSettings();
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
                ip VARCHAR(45) UNIQUE NOT NULL
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

        // 2. Check if IP is blocked
        $stmt = $this->conn->prepare("SELECT * FROM blocked_ips WHERE ip=?");
        $stmt->bind_param("s", $ip);
        $stmt->execute();
        if ($stmt->get_result()->num_rows > 0) {
            return false;
        }

        // 3. Country restriction
        $allowedCountries = explode(',', $this->getSetting('allowed_countries'));

        // Skip localhost
        if ($ip !== '127.0.0.1' && $ip !== '::1') {
            $response = @file_get_contents("http://ip-api.com/json/" . $ip);
            if (!$response) return false;

            $data = json_decode($response, true);
            $country = $data['countryCode'] ?? null;

            if (!$country || !in_array($country, $allowedCountries)) {
                return false;
            }
        }

        // 4. Register user
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->conn->prepare("INSERT INTO users (user_name, password, role) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $hash, $role);
        return $stmt->execute();
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
            return false;
        }

        $user = $res->fetch_assoc();

        if (password_verify($password, $user['password'])) {
            $_SESSION['ROLE'] = $user['role'];
            $_SESSION['ID'] = $user['id'];
            session_regenerate_id(true);
            $this->resetAttempts($username);
            return true;
        }

        $this->increaseAttempts($username, $ip);
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
    }

    public function resetAttempts($username) {
        $stmt = $this->conn->prepare("DELETE FROM login_attempts WHERE user_name=?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
    }

    /* ============================================================
       LOGOUT
       ============================================================ */
    public function logout() {
        session_unset();
        session_destroy();
        header("Location:index.php");
        exit();
    }
}
?>

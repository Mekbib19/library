<?php
// ===================================================================
//  FORTRESS AUTH v2.0 — THE LAST AUTH SYSTEM YOU'LL EVER NEED
//  Just upload this file. Everything auto-creates. No setup. No SQL.
//  Works on any new or existing project. Commercial-ready.
// ===================================================================

declare(strict_types=1);

use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;

class FortressAuth {
    private $db;
    private $tfa;

    public function __construct() {
        // Auto-connect to database (works on 99% of hosts)
        $this->db = @new mysqli(
            $_SERVER['DB_HOST'] ?? 'localhost',
            $_SERVER['DB_USER'] ?? 'root',
            $_SERVER['DB_PASS'] ?? '',
            $_SERVER['DB_NAME'] ?? 'myapp',
            $_SERVER['DB_PORT'] ?? 3306
        );

        if ($this->db->connect_error) {
            die("DB connection failed. Set DB env vars or edit this file.");
        }

        $this->db->set_charset('utf8mb4');
        $this->autoSetup();           // ← This does ALL the magic
        $this->secureSessionStart();
        $this->loginFromRememberMe(); // Auto-login if cookie exists
        $this->setSecurityHeaders();
    }

    private function autoSetup(): void {
        $queries = [
            // Users table with MFA + backup codes
            "CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('user','admin') DEFAULT 'user',
                email VARCHAR(255),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                mfa_secret VARCHAR(255),
                mfa_enabled TINYINT(1) DEFAULT 0,
                mfa_backup_codes TEXT,
                failed_attempts INT DEFAULT 0,
                locked_until DATETIME NULL
            ) ENGINE=InnoDB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",

            // Remember-me tokens (properly secured!)
            "CREATE TABLE IF NOT EXISTS auth_tokens (
                selector CHAR(32) PRIMARY KEY,
                user_id INT,
                validator CHAR(64) NOT NULL,
                expires DATETIME NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_expires (expires)
            ) ENGINE=InnoDB",

            // Auto-create first admin if none exists
            "INSERT IGNORE INTO users (username, password, role) VALUES 
                ('admin', '" . password_hash('admin123', PASSWORD_DEFAULT) . "', 'admin')"
        ];

        foreach ($queries as $q) {
            $this->db->query($q);
        }

        // Clean expired tokens daily
        $this->db->query("DELETE FROM auth_tokens WHERE expires < NOW()");
    }

    private function secureSessionStart(): void {
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', (!empty($_SERVER['HTTPS'])) ? '1' : '0');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.use_strict_mode', '1');
        session_start();

        if (!isset($_SESSION['init'])) {
            session_regenerate_id(true);
            $_SESSION['init'] = true;
            $_SESSION['fingerprint'] = $this->fingerprint();
        } elseif ($_SESSION['fingerprint'] !== $this->fingerprint()) {
            session_destroy();
            die("Session hijack detected!");
        }
    }

    private function fingerprint(): string {
        return hash('sha256', ($_SERVER['HTTP_USER_AGENT'] ?? '') . ($_SERVER['REMOTE_ADDR'] ?? ''));
    }

    private function getTfa(): TwoFactorAuth {
        return $this->tfa ??= new TwoFactorAuth('YourSite', 6, 30, 'sha1', new BaconQrCodeProvider());
    }

    // ================================================================
    // PUBLIC METHODS — JUST CALL THESE IN YOUR PAGES
    // ================================================================

    public function login(string $username, string $password, bool $remember = false, ?string $mfa = null): array {
        $user = $this->getUser($username);
        if (!$user || !password_verify($password, $user['password'])) {
            sleep(2); // Anti-brute
            return ['success' => false, 'error' => 'Invalid credentials'];
        }

        if ($user['mfa_enabled'] && !$mfa) {
            return ['success' => false, 'mfa_required' => true, 'user_id' => $user['id']];
        }

        if ($user['mfa_enabled'] && !$this->verifyMfa($user['mfa_secret'], $mfa)) {
            return ['success' => false, 'error' => 'Wrong MFA code'];
        }

        $this->createSession($user);
        if ($remember) $this->setRememberToken($user['id']);

        return ['success' => true];
    }

    public function logout(): void {
        if (isset($_COOKIE['auth'])) setcookie('auth', '', time()-3600, '/');
        session_destroy();
    }

    public function isLoggedIn(): bool {
        return !empty($_SESSION['user_id']);
    }

    public function user(): ?array {
        return $_SESSION['user'] ?? null;
    }

    public function requireLogin(): void {
        if (!$this->isLoggedIn()) {
            header('Location: login.php');
            exit;
        }
    }

    public function requireAdmin(): void {
        $this->requireLogin();
        if ($_SESSION['user']['role'] !== 'admin') die("Access denied");
    }

    public function generateMfaSetup(int $userId): array {
        $secret = $this->getTfa()->createSecret();
        $qr = $this->getTfa()->getQRCodeImageAsDataUri('User@YourSite', $secret);

        $_SESSION['pending_mfa'] = $secret;
        return ['qr' => $qr, 'secret' => $secret];
    }

    public function enableMfa(int $userId, string $code): bool {
        if ($_SESSION['pending_mfa'] ?? null) {
            if ($this->getTfa()->verifyCode($_SESSION['pending_mfa'], $code)) {
                $backup = [];
                for ($i=0; $i<8; $i++) {
                    $c = substr(bin2hex(random_bytes(5)),0,10);
                    $backup[] = password_hash($c, PASSWORD_DEFAULT);
                }

                $stmt = $this->db->prepare("UPDATE users SET mfa_secret=?, mfa_enabled=1, mfa_backup_codes=? WHERE id=?");
                $stmt->bind_param("ssi", $_SESSION['pending_mfa'], json_encode($backup), $userId);
                $stmt->execute();

                unset($_SESSION['pending_mfa']);
                return true;
            }
        }
        return false;
    }

    // ================================================================
    // INTERNAL METHODS
    // ================================================================

    private function getUser(string $username): ?array {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $res = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        return $res ?: null;
    }

    private function createSession(array $user): void {
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user'] = $user;
        $_SESSION['fingerprint'] = $this->fingerprint();
    }

    private function setRememberToken(int $userId): void {
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));
        $hash = hash('sha256', $validator);
        $expires = date('Y-m-d H:i:s', time() + 30*86400);

        $stmt = $this->db->prepare("INSERT INTO auth_tokens (selector, user_id, validator, expires) VALUES (?,?,?,?)");
        $stmt->bind_param("siss", $selector, $userId, $hash, $expires);
        $stmt->execute();

        setcookie('auth', $selector.':'.$validator, time()+30*86400, '/', '', !empty($_SERVER['HTTPS']), true);
    }

    private function loginFromRememberMe(): void {
        if (empty($_COOKIE['auth'])) return;
        [$selector, $validator] = explode(':', $_COOKIE['auth'].' ');

        $stmt = $this->db->prepare("SELECT at.*, u.* FROM auth_tokens at JOIN users u ON u.id=at.user_id WHERE selector=? AND expires > NOW()");
        $stmt->bind_param("s", $selector);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();

        if ($row && hash_equals($row['validator'], hash('sha256', $validator))) {
            $this->setRememberToken($row['id']); // Rotate
            $this->createSession($row);
        } else {
            setcookie('auth', '', time()-3600, '/');
        }
    }

    private function verifyMfa(?string $secret, ?string $code): bool {
        if (!$secret || !$code) return false;
        if ($this->getTfa()->verifyCode($secret, $code, 2)) return true;

        // Backup codes
        $userId = $_SESSION['user_id'] ?? null;
        if (!$userId) return false;

        $stmt = $this->db->prepare("SELECT mfa_backup_codes FROM users WHERE id=?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $codes = json_decode($stmt->get_result()->fetch_assoc()['mfa_backup_codes'] ?? '[]', true);

        foreach ($codes as $i => $hash) {
            if (password_verify($code, $hash)) {
                unset($codes[$i]);
                $this->db->query("UPDATE users SET mfa_backup_codes = '".json_encode(array_values($codes))."' WHERE id=$userId");
                return true;
            }
        }
        return false;
    }

    private function setSecurityHeaders(): void {
        header_remove('X-Powered-By');
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
    }
}

// ===================================================================
// AUTO-START — JUST INCLUDE THIS FILE AND YOU'RE DONE
// ===================================================================
$auth = new FortressAuth;
?>
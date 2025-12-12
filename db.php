<?php
/**
 * Return a mysqli connection using environment variables or defaults.
 * Throws RuntimeException on failure so callers can handle errors.
 */
function get_db(): mysqli {
    $host = $_SERVER['DB_HOST'] ?? 'localhost';
    $user = $_SERVER['DB_USER'] ?? 'root';
    $pass = $_SERVER['DB_PASS'] ?? '';
    $name = $_SERVER['DB_NAME'] ?? 'Auth';
    $port = (int)($_SERVER['DB_PORT'] ?? 3306);

    $db = @new mysqli($host, $user, $pass, $name, $port);
    if ($db->connect_error) {
        throw new RuntimeException('DB connection failed: ' . $db->connect_error);
    }

    $db->set_charset('utf8mb4');
    return $db;
}

<?php
/*  Module: User database manager
 *  Description: SQLite user & token management for simple apps
 *  Security: prepared statements, hashed tokens, secure cookies, TTL, rate-limit integrated
 */

declare(strict_types=1);

// start session early
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

date_default_timezone_set('Asia/Kolkata');

// ── Configuration ──────────────────────────────────────────────────────────────
define('DB_DIR_PATH', dirname(__FILE__));
define('ACTIONS_DIR', dirname(__FILE__).'/auth_actions');


// Cookie settings
define('COOKIE_NAME', 'common');
define('COOKIE_TTL_SECONDS', 86400 * 7);             // 7 days
define('COOKIE_SAMESITE', 'Strict');                 // 'Lax' or 'None' (None requires Secure=true)
define('COOKIE_SECURE', (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'));  // true if HTTPS
define('COOKIE_HTTPONLY', true);

// Token settings
define('TOKEN_BYTES', 32);                           // 32 -> 64 hex chars
define('TOKEN_TTL_SQLITE_CLAUSE', "-7 days");        // TTL clause for sqlite DATETIME('now', ...)
const ALLOWED_ROLES = ['admin', 'user'];
const DEFAULT_ROLE = 'user';

// ── Value Objects ──────────────────────────────────────────────────────────────
class user {
    public string $username;
    public string $name;
    public string $role;
    public string $created;
    public string $last_updated;

    function __construct(string $username, string $name, string $role, string $created, string $last_updated) {
        $this->username     = $username;
        $this->name     	= $name;
        $this->role         = $role;
        $this->created      = $created;
        $this->last_updated = $last_updated;
    }
}

class db_result {
    public bool $success = false;
    public string $response_type = 'bool';
    public $response = null;
    public ?string $error_message = null;
}

// ── Main DB Class ──────────────────────────────────────────────────────────────
class userdb {
    public bool $connection_status = false;
    private ?SQLite3 $connection = null;

    function __construct() {
        $dbPath = DB_DIR_PATH . '/users.db';
        if (file_exists($dbPath)) {
            $this->connection = new SQLite3($dbPath, SQLITE3_OPEN_READWRITE);
            if ($this->connection) {
                $this->connection->busyTimeout(3000);
                @$this->connection->exec('PRAGMA foreign_keys = ON;');
                $this->connection_status = true;
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────
    private function now(): string {
        return date('Y-m-d H:i:s');
    }

    private function hashToken(string $rawToken): string {
        return hash('sha256', $rawToken);
    }

    private function setCookieSecure(string $value): void {
        // Use array options (PHP 7.3+). Omit domain so cookie defaults to host.
        @setcookie(COOKIE_NAME, $value, [
            'expires'  => time() + COOKIE_TTL_SECONDS,
            'path'     => '/',
            'secure'   => COOKIE_SECURE,
            'httponly' => COOKIE_HTTPONLY,
            'samesite' => COOKIE_SAMESITE,
        ]);
        // keep runtime in sync
        $_COOKIE[COOKIE_NAME] = $value;
    }

    private function clearCookie(): void {
        @setcookie(COOKIE_NAME, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'secure'   => COOKIE_SECURE,
            'httponly' => COOKIE_HTTPONLY,
            'samesite' => COOKIE_SAMESITE,
        ]);
        unset($_COOKIE[COOKIE_NAME]);
    }

    private function usernameExists(string $username): bool {
        $stmt = $this->connection->prepare('SELECT 1 FROM users WHERE username = :u LIMIT 1');
        $stmt->bindValue(':u', $username, SQLITE3_TEXT);
        $row = $stmt->execute()->fetchArray(SQLITE3_NUM);
        return (bool)$row;
    }

    private function fetchUserRow(string $username): ?array {
        $stmt = $this->connection->prepare('SELECT username, name, password, role, created, last_updated FROM users WHERE username = :u LIMIT 1');
        $stmt->bindValue(':u', $username, SQLITE3_TEXT);
        $res = $stmt->execute();
        $row = $res->fetchArray(SQLITE3_ASSOC);
        return $row ?: null;
    }

    private function tokenRowFromCookie(): ?array {
        if (!$this->connection_status || empty($_COOKIE[COOKIE_NAME])) return null;

        $rawToken = $_COOKIE[COOKIE_NAME];
        $tokenHash = $this->hashToken($rawToken);

        // Enforce TTL via created timestamp
        $sql = "
            SELECT auth_tokens.username AS t_user, auth_tokens.created AS t_created, users.role, users.created, users.last_updated
            FROM auth_tokens
            JOIN users ON auth_tokens.username = users.username
            WHERE auth_tokens.token = :thash
              AND auth_tokens.created >= DATETIME('now', :ttlClause)
            LIMIT 1
        ";
        $stmt = $this->connection->prepare($sql);
        $stmt->bindValue(':thash', $tokenHash, SQLITE3_TEXT);
        $stmt->bindValue(':ttlClause', TOKEN_TTL_SQLITE_CLAUSE, SQLITE3_TEXT);
        $res = $stmt->execute();
        $row = $res->fetchArray(SQLITE3_ASSOC);
        return $row ?: null;
    }

    private function ensureRoleAllowed(string $role): bool {
        return in_array($role, ALLOWED_ROLES, true);
    }

    // ── Rate-limiting helpers (login_attempts table) ──────────────────────────
    private function record_login_attempt(string $username, string $ip): void {
        $stmt = $this->connection->prepare("INSERT INTO login_attempts (username, ip, attempted_at) VALUES (:username, :ip, :ts)");
        $stmt->bindValue(":username", $username, SQLITE3_TEXT);
        $stmt->bindValue(":ip", $ip, SQLITE3_TEXT);
        $stmt->bindValue(":ts", $this->now(), SQLITE3_TEXT);
        $stmt->execute();
    }

    private function too_many_attempts(string $ip, int $limit = 50, int $minutes = 5): bool {
        $stmt = $this->connection->prepare("
            SELECT COUNT(*) as cnt FROM login_attempts
            WHERE ip = :ip AND attempted_at > datetime('now', :window)
        ");
        $stmt->bindValue(":ip", $ip, SQLITE3_TEXT);
        $stmt->bindValue(":window", "-$minutes minutes", SQLITE3_TEXT);
        $res = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        return ($res && isset($res['cnt']) && (int)$res['cnt'] >= $limit);
    }

    private function clear_login_attempts(string $ip): void {
        $stmt = $this->connection->prepare("DELETE FROM login_attempts WHERE ip = :ip");
        $stmt->bindValue(":ip", $ip, SQLITE3_TEXT);
        $stmt->execute();
    }

    // ── Public API (methods) ───────────────────────────────────────────────────

    // add_user(username, password, name, role)
    function add_user($username, $password, $name, $role = DEFAULT_ROLE): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }
        if (!$this->check_if_admin())  { $result->error_message = 'Action restricted'; return $result; }

        $username = trim((string)$username);
        $password = (string)$password;
        $name     = trim((string)$name);
        $role     = strtolower(trim((string)$role));

        if ($username === '' || $password === '' || $name === '') { $result->error_message = 'Username, password, and name required'; return $result; }
        if (!$this->ensureRoleAllowed($role)) { $result->error_message = 'Invalid role'; return $result; }
        if ($this->usernameExists($username)) { $result->error_message = 'Username already taken'; return $result; }

        $now = $this->now();
        $hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = $this->connection->prepare('INSERT INTO users (username, password, name, created, last_updated, role) VALUES (:u, :p, :n, :c, :lu, :r)');
        $stmt->bindValue(':u', $username, SQLITE3_TEXT);
        $stmt->bindValue(':p', $hash, SQLITE3_TEXT);
        $stmt->bindValue(':n', $name, SQLITE3_TEXT);
        $stmt->bindValue(':c', $now, SQLITE3_TEXT);
        $stmt->bindValue(':lu', $now, SQLITE3_TEXT);
        $stmt->bindValue(':r', $role, SQLITE3_TEXT);
        $ok = $stmt->execute();

        if ($ok) { $result->success = true; } else { $result->error_message = 'Failed to add user'; }
        return $result;
    }

    // delete_user (not admin)
    function delete_user($username): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }
        if (!$this->check_if_admin())  { $result->error_message = 'Action restricted'; return $result; }

        $username = trim((string)$username);
        $row = $this->fetchUserRow($username);
        if (!$row) { $result->error_message = 'User not found'; return $result; }
        if ($row['role'] === 'admin') { $result->error_message = 'Cannot delete admin'; return $result; }

        $stmt = $this->connection->prepare('DELETE FROM users WHERE username = :u');
        $stmt->bindValue(':u', $username, SQLITE3_TEXT);
        $ok = $stmt->execute();

        if ($ok) {
            $stmt2 = $this->connection->prepare('DELETE FROM auth_tokens WHERE username = :u');
            $stmt2->bindValue(':u', $username, SQLITE3_TEXT);
            $stmt2->execute();
            $result->success = true;
        } else {
            $result->error_message = 'Cannot delete user';
        }
        return $result;
    }

// change_password (by logged-in user, requiring old password)
function change_password($oldp, $newp): db_result {
    $result = new db_result();
    if (!$this->connection_status) {
        $result->error_message = 'Connection error';
        return $result;
    }

    $oldp = (string)$oldp;
    $newp = (string)$newp;
    if ($oldp === '' || $newp === '') {
        $result->error_message = 'Old and new password required';
        return $result;
    }

    $trow = $this->tokenRowFromCookie();
    if (!$trow) {
        $result->error_message = 'Action restricted to logged-in users';
        return $result;
    }

    // Fetch current password hash
    $stmt = $this->connection->prepare('SELECT password FROM users WHERE username = :u');
    $stmt->bindValue(':u', $trow['t_user'], SQLITE3_TEXT);
    $res = $stmt->execute();
    $row = $res ? $res->fetchArray(SQLITE3_ASSOC) : null;

    if (!$row || !password_verify($oldp, $row['password'])) {
        $result->error_message = 'Old password incorrect';
        return $result;
    }

    // Update to new password
    $hash = password_hash($newp, PASSWORD_DEFAULT);
    $stmt = $this->connection->prepare('UPDATE users SET password = :p, last_updated = :lu WHERE username = :u');
    $stmt->bindValue(':p', $hash, SQLITE3_TEXT);
    $stmt->bindValue(':lu', $this->now(), SQLITE3_TEXT);
    $stmt->bindValue(':u', $trow['t_user'], SQLITE3_TEXT);
    $ok = $stmt->execute();

    if ($ok) {
        $result->success = true;
    } else {
        $result->error_message = 'Cannot update password';
    }
    return $result;
}


    // change_password_by_admin
    function change_password_by_admin($u, $np): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }
        if (!$this->check_if_admin())  { $result->error_message = 'Action restricted'; return $result; }

        $u = trim((string)$u);
        $np = (string)$np;

        $row = $this->fetchUserRow($u);
        if (!$row) { $result->error_message = 'User not found'; return $result; }

        $hash = password_hash($np, PASSWORD_DEFAULT);
        $stmt = $this->connection->prepare('UPDATE users SET password = :p, last_updated = :lu WHERE username = :u');
        $stmt->bindValue(':p', $hash, SQLITE3_TEXT);
        $stmt->bindValue(':lu', $this->now(), SQLITE3_TEXT);
        $stmt->bindValue(':u', $u, SQLITE3_TEXT);
        $ok = $stmt->execute();

        if ($ok) { $result->success = true; } else { $result->error_message = 'Cannot update password'; }
        return $result;
    }

    // update_user_by_admin
function update_user_by_admin($u, $name, $role): db_result {

    $result = new db_result();
    if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }
    if (!$this->check_if_admin())  { $result->error_message = 'Action restricted'; return $result; }

    $u    = trim((string)$u);
    $name = trim((string)$name);
    $role = strtolower(trim((string)$role));

    if ($u === '' || $name === '') {
        $result->error_message = 'Username and name required';
        return $result;
    }
    if (!$this->ensureRoleAllowed($role)) { 
        $result->error_message = 'Invalid role'; 
        return $result; 
    }

    $row = $this->fetchUserRow($u);
    if (!$row) { 
        $result->error_message = 'User not found'; 
        return $result; 
    }

    $stmt = $this->connection->prepare(
        'UPDATE users SET name = :n, role = :r, last_updated = :lu WHERE username = :u'
    );
    $stmt->bindValue(':n', $name, SQLITE3_TEXT);
    $stmt->bindValue(':r', $role, SQLITE3_TEXT);
    $stmt->bindValue(':lu', $this->now(), SQLITE3_TEXT);
    $stmt->bindValue(':u', $u, SQLITE3_TEXT);

    $ok = $stmt->execute();

    if ($ok) { 
        $result->success = true; 
    } else { 
        $result->error_message = 'Cannot update user'; 
    }
    return $result;
}

    // change_role_by_admin
    function change_role_by_admin($u, $role): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }
        if (!$this->check_if_admin())  { $result->error_message = 'Action restricted'; return $result; }

        $u = trim((string)$u);
        $role = strtolower(trim((string)$role));
        if (!$this->ensureRoleAllowed($role)) { $result->error_message = 'Invalid role'; return $result; }

        $row = $this->fetchUserRow($u);
        if (!$row) { $result->error_message = 'User not found'; return $result; }

        $stmt = $this->connection->prepare('UPDATE users SET role = :r, last_updated = :lu WHERE username = :u');
        $stmt->bindValue(':r', $role, SQLITE3_TEXT);
        $stmt->bindValue(':lu', $this->now(), SQLITE3_TEXT);
        $stmt->bindValue(':u', $u, SQLITE3_TEXT);
        $ok = $stmt->execute();

        if ($ok) { $result->success = true; } else { $result->error_message = 'Cannot update role'; }
        return $result;
    }

    // get_user (no password)
    function get_user($name): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }

        $name = trim((string)$name);
        $stmt = $this->connection->prepare('SELECT username, name, role, created, last_updated FROM users WHERE username = :u LIMIT 1');
        $stmt->bindValue(':u', $name, SQLITE3_TEXT);
        $res = $stmt->execute();
        $r = $res->fetchArray(SQLITE3_ASSOC);

        if ($r) {
            $result->success = true;
            $result->response_type = 'user';
            $result->response = new user($r['username'], $r['name'], $r['role'], $r['created'], $r['last_updated']);
        } else {
            $result->error_message = 'No result from database';
        }
        return $result;
    }

    // get_logged_in_user
    function get_logged_in_user(): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }

        $trow = $this->tokenRowFromCookie();
        if ($trow) {
            $result->success = true;
            $result->response_type = 'user';
            $u = $this->get_user($trow['t_user']);
            if($u)
            {
            	$result->response = $u->response;
            }
            
        } else {
            $result->error_message = 'Not logged in';
        }
        return $result;
    }

    // get_all_users
    function get_all_users(): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }

        $q = $this->connection->query('SELECT username, name, role, created, last_updated FROM users ORDER BY username ASC');
        $arr = [];
        while ($a = $q->fetchArray(SQLITE3_ASSOC)) {
            $arr[] = new user($a['username'], $a['name'], $a['role'], $a['created'], $a['last_updated']);
        }
        $result->success = true;
        $result->response_type = 'user_array';
        $result->response = $arr;
        return $result;
    }

    function check_login_status(): bool {
        return (bool)$this->tokenRowFromCookie();
    }

    function check_if_admin(): bool {
        $trow = $this->tokenRowFromCookie();
        return $trow && $trow['role'] === 'admin';
    }

    // generate_token: stores hashed token in DB, raw token in cookie
    private function generate_token(string $username): bool {
        $raw = bin2hex(random_bytes(TOKEN_BYTES));
        $hash = $this->hashToken($raw);

        $stmt = $this->connection->prepare('INSERT INTO auth_tokens (token, username, created) VALUES (:t, :u, :c)');
        $stmt->bindValue(':t', $hash, SQLITE3_TEXT);
        $stmt->bindValue(':u', $username, SQLITE3_TEXT);
        $stmt->bindValue(':c', $this->now(), SQLITE3_TEXT);
        $ok = $stmt->execute();

        if ($ok) {
            // regenerate session id to prevent fixation
            if (session_status() !== PHP_SESSION_NONE) {
                session_regenerate_id(true);
            }
            // rotate CSRF token after login
            $_SESSION['csrf_token'] = generate_csrf_token();
            $this->setCookieSecure($raw); // raw token in cookie; hashed token in DB
            return true;
        }
        return false;
    }

    // login
    function login($u, $p): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }

        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if ($this->too_many_attempts($ip)) {
            $result->error_message = 'Too many attempts';
            return $result;
        }

        if ($this->check_login_status()) { $result->error_message = 'Already logged in'; return $result; }

        $u = trim((string)$u);
        $p = (string)$p;

        $row = $this->fetchUserRow($u);
        if (!$row) {
            $this->record_login_attempt($u, $ip);
            $result->error_message = 'Incorrect username or password';
            return $result;
        }

        if (!password_verify($p, $row['password'])) {
            $this->record_login_attempt($u, $ip);
            $result->error_message = 'Incorrect username or password';
            return $result;
        }

        // rehash if needed
        if (password_needs_rehash($row['password'], PASSWORD_DEFAULT)) {
            $newHash = password_hash($p, PASSWORD_DEFAULT);
            $s = $this->connection->prepare('UPDATE users SET password = :p WHERE username = :u');
            $s->bindValue(':p', $newHash, SQLITE3_TEXT);
            $s->bindValue(':u', $u, SQLITE3_TEXT);
            $s->execute();
        }

        if ($this->generate_token($u)) {
            $this->clear_login_attempts($ip);
            $result->success = true;
        } else {
            $result->error_message = 'Cannot generate token';
        }
        return $result;
    }

    // logout
    function logout(): db_result {
        $result = new db_result();
        if (!$this->connection_status) { $result->error_message = 'Connection error'; return $result; }
        if (empty($_COOKIE[COOKIE_NAME])) { $result->error_message = 'Not logged in'; return $result; }

        $rawToken = $_COOKIE[COOKIE_NAME];
        $tokenHash = $this->hashToken($rawToken);

        $stmt = $this->connection->prepare('DELETE FROM auth_tokens WHERE token = :t');
        $stmt->bindValue(':t', $tokenHash, SQLITE3_TEXT);
        $ok = $stmt->execute();

        $this->clearCookie();

        if ($ok) { $result->success = true; } else { $result->error_message = 'Logout failed'; }
        return $result;
    }
} // end class userdb

// ── CSRF helpers (global) ─────────────────────────────────────────────────────
function generate_csrf_token(): string {
    return bin2hex(random_bytes(TOKEN_BYTES));
}

function csrf_protect(): void {
    if (session_status() === PHP_SESSION_NONE) session_start();

    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = generate_csrf_token();
        $_SESSION['csrf_token_created'] = time();
    }

    // validate for state-changing methods
    $unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'];
    if (in_array($_SERVER['REQUEST_METHOD'], $unsafe, true)) {
        $token = $_POST['csrf_token'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null);
        if (!$token || $token !== ($_SESSION['csrf_token'] ?? '')) {
            http_response_code(403);
            die('CSRF token mismatch');
        }
    }
}

/* Helper functions */
$db = new userdb();
$user = null;
$is_loggedin = false;

if($db->check_login_status())
{
    $is_loggedin = true;
    $u = $db->get_logged_in_user();
    if($u->success)
    {
        $user = $u->response;
    }
}
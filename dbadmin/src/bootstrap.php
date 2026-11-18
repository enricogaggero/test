<?php
declare(strict_types=1);

const APP_ROOT = __DIR__ . '/..';
const APP_NAME = 'DB Admin MCP';
const APP_VERSION = '1.0.0';

require __DIR__ . '/TargetDb.php';
require __DIR__ . '/Analyzer.php';
require __DIR__ . '/S3.php';
require __DIR__ . '/Backup.php';
require __DIR__ . '/McpServer.php';

function cfg(): array
{
    static $c = null;
    if ($c === null) {
        $f = getenv('DBADMIN_CONFIG') ?: APP_ROOT . '/config.php';
        if (!is_file($f)) {
            throw new RuntimeException('config.php mancante: copiare config.sample.php');
        }
        $c = require $f;
    }
    return $c;
}

function appdb(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $d = cfg()['db'];
        $dsn = "mysql:host={$d['host']};port={$d['port']};dbname={$d['name']};charset=" . ($d['charset'] ?? 'utf8mb4');
        $pdo = new PDO($dsn, $d['user'], $d['pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

function q(string $sql, array $params = []): PDOStatement
{
    $st = appdb()->prepare($sql);
    $st->execute($params);
    return $st;
}

function h(mixed $s): string
{
    return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
}

// ---------- cifratura credenziali ----------

function app_key(): string
{
    $k = base64_decode((string)(cfg()['app_key'] ?? ''), true);
    if ($k === false || strlen($k) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        throw new RuntimeException('app_key non valida in config.php (generarla con: php bin/install.php --genkey)');
    }
    return $k;
}

function enc(string $plain): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, app_key()));
}

function dec(string $stored): string
{
    $raw = base64_decode($stored, true);
    if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
        throw new RuntimeException('Dato cifrato non valido');
    }
    $plain = sodium_crypto_secretbox_open(
        substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
        substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
        app_key()
    );
    if ($plain === false) {
        throw new RuntimeException('Impossibile decifrare: app_key diversa da quella usata per salvare');
    }
    return $plain;
}

// ---------- richiesta HTTP ----------

function client_ip(): string
{
    if (PHP_SAPI === 'cli') {
        return 'cli';
    }
    if (!empty(cfg()['security']['trust_proxy']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    return !empty(cfg()['security']['trust_proxy'])
        && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
}

/** Controlli comuni a GUI e MCP: HTTPS obbligatorio e allowlist IP. Ritorna il motivo del rifiuto o null. */
function request_denied_reason(): ?string
{
    $s = cfg()['security'] ?? [];
    if (($s['require_https'] ?? true) && !is_https()) {
        return 'HTTPS obbligatorio';
    }
    $ips = $s['allowed_ips'] ?? [];
    if ($ips && !in_array(client_ip(), $ips, true)) {
        return 'Indirizzo IP non autorizzato';
    }
    return null;
}

// ---------- utenti e login ----------

function audit(string $channel, ?string $username, string $action, ?string $conn = null, ?string $detail = null): void
{
    try {
        q('INSERT INTO dba_audit (username, channel, action, conn_name, detail, ip) VALUES (?,?,?,?,?,?)',
            [$username, $channel, $action, $conn, $detail === null ? null : mb_substr($detail, 0, 4000), client_ip()]);
    } catch (Throwable) {
        // l'audit non deve mai bloccare l'operazione
    }
}

/**
 * Verifica user/password con blocco anti brute-force.
 * $need = colonna permesso richiesta ('can_gui' | 'can_mcp').
 * Ritorna la riga utente oppure lancia RuntimeException con messaggio generico.
 */
function login_check(string $username, string $password, string $need, string $channel): array
{
    $s    = cfg()['security'] ?? [];
    $max  = (int)($s['max_failures'] ?? 5);
    $mins = (int)($s['lock_minutes'] ?? 15);
    $ip   = client_ip();
    $username = mb_substr(trim($username), 0, 64);

    $fails = (int)q(
        "SELECT COUNT(*) FROM dba_login_attempts
          WHERE ok = 0 AND created_at > NOW() - INTERVAL $mins MINUTE AND (username = ? OR ip = ?)",
        [$username, $ip]
    )->fetchColumn();
    if ($fails >= $max) {
        audit($channel, $username, 'login_blocked');
        throw new RuntimeException("Troppi tentativi falliti: riprovare tra $mins minuti");
    }

    $u = q('SELECT * FROM dba_users WHERE username = ?', [$username])->fetch();
    // hash fittizio: tempi di risposta uguali anche per utenti inesistenti
    $hash = $u['password_hash'] ?? '$2y$10$abcdefghijklmnopqrstuuJ1m0yC0V7g3zQmB0c6X6l0QkN1b8w2K';
    $ok = password_verify($password, $hash) && $u && $u['active'] && $u[$need];

    q('INSERT INTO dba_login_attempts (username, ip, ok) VALUES (?,?,?)', [$username, $ip, $ok ? 1 : 0]);
    if (!$ok) {
        audit($channel, $username, 'login_failed');
        throw new RuntimeException('Credenziali non valide');
    }
    q('UPDATE dba_users SET last_login_at = NOW() WHERE id = ?', [$u['id']]);
    q('DELETE FROM dba_login_attempts WHERE created_at < NOW() - INTERVAL 30 DAY');
    audit($channel, $username, 'login_ok');
    return $u;
}

// ---------- connessioni registrate e impostazioni ----------

function conn_all(): array
{
    return q('SELECT * FROM dba_connections ORDER BY name')->fetchAll();
}

function conn_get(string|int $nameOrId): array
{
    $c = is_int($nameOrId) || ctype_digit((string)$nameOrId)
        ? q('SELECT * FROM dba_connections WHERE id = ?', [(int)$nameOrId])->fetch()
        : q('SELECT * FROM dba_connections WHERE name = ?', [$nameOrId])->fetch();
    if (!$c) {
        throw new RuntimeException("Connessione '$nameOrId' non trovata (usare list_connections)");
    }
    return $c;
}

function setting(string $k, ?string $default = null): ?string
{
    $v = q('SELECT v FROM dba_settings WHERE k = ?', [$k])->fetchColumn();
    return $v === false || $v === null ? $default : (string)$v;
}

function setting_set(string $k, ?string $v): void
{
    q('INSERT INTO dba_settings (k, v) VALUES (?,?) ON DUPLICATE KEY UPDATE v = VALUES(v)', [$k, $v]);
}

/** Configurazione S3 dalle impostazioni salvate in GUI (secret decifrata). */
function s3_config(): array
{
    $secret = setting('s3_secret_enc');
    return [
        'endpoint'   => setting('s3_endpoint', ''),
        'region'     => setting('s3_region', 'eu-south-1'),
        'bucket'     => setting('s3_bucket', ''),
        'access_key' => setting('s3_access_key', ''),
        'secret'     => $secret ? dec($secret) : '',
        'prefix'     => trim((string)setting('s3_prefix', 'mysql-backup'), '/'),
        'path_style' => setting('s3_path_style', '0') === '1',
        'sse'        => setting('s3_sse', '0') === '1',
        'retention'  => (int)setting('s3_retention_days', '30'),
    ];
}

function human_bytes(int|float|null $b): string
{
    if ($b === null) {
        return '-';
    }
    $u = ['B', 'KB', 'MB', 'GB', 'TB'];
    $i = 0;
    while ($b >= 1024 && $i < 4) {
        $b /= 1024;
        $i++;
    }
    return round($b, $i ? 1 : 0) . ' ' . $u[$i];
}

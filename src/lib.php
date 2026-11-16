<?php
declare(strict_types=1);

function cfg(): array
{
    static $c = null;
    if ($c === null) {
        $f = __DIR__ . '/../config.php';
        if (!is_file($f)) {
            http_response_code(500);
            exit('config.php mancante: copiare config.sample.php');
        }
        $c = require $f;
    }
    return $c;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $d = cfg()['db'];
        $dsn = "mysql:host={$d['host']};port={$d['port']};dbname={$d['name']};charset={$d['charset']}";
        $pdo = new PDO($dsn, $d['user'], $d['pass'], [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

/** Nome tabella/colonna sicuro (da config, mai da input utente). */
function ident(string $s): string
{
    if (!preg_match('/^[A-Za-z0-9_]+$/', $s)) {
        throw new RuntimeException("Identificatore non valido: $s");
    }
    return "`$s`";
}

function normalize_plate(string $p): string
{
    return strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $p) ?? '');
}

function plate_valid(string $p): bool
{
    return (bool)preg_match('/^[A-Z0-9]{4,10}$/', $p);
}

function find_vehicle(string $plate): ?array
{
    $e = cfg()['egauto'];
    $cols = array_merge([$e['id_col'], $e['plate_col']], $e['info_cols'] ?? []);
    $sel = implode(',', array_map('ident', array_unique($cols)))
         . ',`gps_lat`,`gps_lng`,`gps_accuracy_m`,`gps_source`,`gps_updated_at`';
    $pc = ident($e['plate_col']);
    $sql = "SELECT $sel FROM " . ident($e['table'])
         . " WHERE UPPER(REPLACE(REPLACE(REPLACE($pc,' ',''),'-',''),'.','')) = ? LIMIT 1";
    $st = db()->prepare($sql);
    $st->execute([normalize_plate($plate)]);
    $r = $st->fetch();
    return $r ?: null;
}

function save_position(mixed $id, float $lat, float $lng, ?float $acc, string $source): void
{
    if ($lat < -90 || $lat > 90 || $lng < -180 || $lng > 180) {
        throw new InvalidArgumentException('Coordinate fuori range');
    }
    $e = cfg()['egauto'];
    $sql = 'UPDATE ' . ident($e['table'])
         . ' SET `gps_lat`=?, `gps_lng`=?, `gps_accuracy_m`=?, `gps_source`=?, `gps_updated_at`=NOW()'
         . ' WHERE ' . ident($e['id_col']) . ' = ?';
    db()->prepare($sql)->execute([round($lat, 7), round($lng, 7), $acc, $source, $id]);
}

function json_out(array $data, int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function session_boot(): void
{
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params(['httponly' => true, 'samesite' => 'Strict',
            'secure' => !empty($_SERVER['HTTPS'])]);
        session_start();
    }
}

function is_logged(): bool
{
    session_boot();
    return !empty($_SESSION['auth']);
}

function csrf_token(): string
{
    session_boot();
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(16));
}

function require_api_auth(bool $post = false): void
{
    if (!is_logged()) {
        json_out(['ok' => false, 'error' => 'Non autenticato'], 401);
    }
    if ($post) {
        $t = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!hash_equals(csrf_token(), $t)) {
            json_out(['ok' => false, 'error' => 'Token CSRF non valido'], 403);
        }
    }
}

function vehicle_public(array $v): array
{
    $e = cfg()['egauto'];
    $info = [];
    foreach ($e['info_cols'] ?? [] as $c) {
        $info[$c] = $v[$c] ?? null;
    }
    return [
        'id'      => $v[$e['id_col']],
        'plate'   => $v[$e['plate_col']],
        'info'    => $info,
        'lat'     => $v['gps_lat'] !== null ? (float)$v['gps_lat'] : null,
        'lng'     => $v['gps_lng'] !== null ? (float)$v['gps_lng'] : null,
        'acc'     => $v['gps_accuracy_m'] !== null ? (float)$v['gps_accuracy_m'] : null,
        'source'  => $v['gps_source'],
        'updated' => $v['gps_updated_at'],
    ];
}

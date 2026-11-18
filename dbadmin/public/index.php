<?php
declare(strict_types=1);
// GUI di amministrazione: connessioni, utenti, backup S3, audit, sessioni MCP.
require __DIR__ . '/../src/bootstrap.php';

try {
    cfg();
    if ($why = request_denied_reason()) {
        http_response_code(403);
        exit(h($why));
    }
} catch (Throwable $e) {
    http_response_code(500);
    exit(h($e->getMessage()));
}

session_set_cookie_params(['httponly' => true, 'secure' => is_https(), 'samesite' => 'Strict', 'path' => '/']);
session_name('dbadmin');
session_start();
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
     . "font-src https://fonts.gstatic.com; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; frame-ancestors 'none'");

$_SESSION['csrf'] ??= bin2hex(random_bytes(32));
$me = $_SESSION['user'] ?? null;
$page = preg_replace('/[^a-z]/', '', (string)($_GET['p'] ?? 'dashboard'));
$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';

function flash(string $type, string $msg): void
{
    $_SESSION['flash'][] = [$type, $msg];
}

function go(string $p): never
{
    header('Location: ?p=' . $p);
    exit;
}

function post(string $k, string $d = ''): string
{
    return trim((string)($_POST[$k] ?? $d));
}

function chk(string $k): int
{
    return isset($_POST[$k]) ? 1 : 0;
}

if ($isPost && !hash_equals($_SESSION['csrf'], (string)($_POST['csrf'] ?? ''))) {
    http_response_code(400);
    exit('Token CSRF non valido: ricaricare la pagina');
}

// ---------------- login / logout ----------------
if ($isPost && post('action') === 'login') {
    try {
        $u = login_check(post('username'), (string)($_POST['password'] ?? ''), 'can_gui', 'gui');
        session_regenerate_id(true);
        $_SESSION['user'] = ['id' => (int)$u['id'], 'username' => $u['username']];
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        go('dashboard');
    } catch (PDOException $e) {
        error_log('[dbadmin] ' . $e->getMessage());
        flash('danger', 'Database applicativo non raggiungibile');
    } catch (RuntimeException $e) {
        flash('danger', $e->getMessage());
    }
    go('login');
}
if ($isPost && post('action') === 'logout') {
    audit('gui', $me['username'] ?? null, 'logout');
    $_SESSION = [];
    session_destroy();
    go('login');
}
if (!$me) {
    $page = 'login';
} elseif (!q('SELECT 1 FROM dba_users WHERE id = ? AND active = 1 AND can_gui = 1', [$me['id']])->fetch()) {
    $_SESSION = [];
    session_destroy();
    go('login');
}

// ---------------- azioni (solo utenti autenticati) ----------------
if ($me && $isPost) {
    $act = post('action');
    $un = $me['username'];
    try {
        switch ($act) {
            case 'conn_save':
                $id = (int)post('id');
                $name = strtolower(post('name'));
                if (!preg_match('/^[a-z0-9][a-z0-9_-]{1,62}$/', $name)) {
                    throw new RuntimeException('Nome non valido: usare lettere minuscole, numeri, _ e - (2-63 caratteri)');
                }
                $port = (int)post('port', '3306');
                if (post('host') === '' || post('db_name') === '' || post('db_user') === '' || $port < 1 || $port > 65535) {
                    throw new RuntimeException('Host, porta, database e utente sono obbligatori');
                }
                $f = [$name, post('host'), $port, post('db_name'), post('db_user'), chk('use_ssl'), chk('allow_write'), chk('backup_enabled'), post('notes') ?: null];
                $pass = (string)($_POST['db_pass'] ?? '');
                if ($id) {
                    q('UPDATE dba_connections SET name=?, host=?, port=?, db_name=?, db_user=?, use_ssl=?, allow_write=?, backup_enabled=?, notes=? WHERE id=?', [...$f, $id]);
                    if ($pass !== '') {
                        q('UPDATE dba_connections SET db_pass_enc=? WHERE id=?', [enc($pass), $id]);
                    }
                } else {
                    q('INSERT INTO dba_connections (name, host, port, db_name, db_user, use_ssl, allow_write, backup_enabled, notes, db_pass_enc) VALUES (?,?,?,?,?,?,?,?,?,?)', [...$f, enc($pass)]);
                }
                audit('gui', $un, $id ? 'conn_update' : 'conn_create', $name);
                flash('success', "Connessione «{$name}» salvata");
                go('connections');
            case 'conn_delete':
                $c = conn_get((int)post('id'));
                q('DELETE FROM dba_connections WHERE id = ?', [$c['id']]);
                audit('gui', $un, 'conn_delete', $c['name']);
                flash('success', "Connessione «{$c['name']}» eliminata");
                go('connections');
            case 'conn_test':
                $c = conn_get((int)post('id'));
                try {
                    $pdo = TargetDb::connect($c, 5);
                    $v = $pdo->query('SELECT VERSION()')->fetchColumn();
                    flash('success', "«{$c['name']}»: connessione riuscita (server $v)");
                } catch (Throwable $e) {
                    flash('danger', "«{$c['name']}»: " . $e->getMessage());
                }
                go('connections');
            case 'backup_now':
                $c = conn_get((int)post('id'));
                new S3(s3_config());
                Backup::spawn((int)$c['id'], 'gui');
                audit('gui', $un, 'backup_now', $c['name']);
                flash('info', "Backup di «{$c['name']}» avviato in background: aggiornare la pagina tra poco per l'esito");
                go('backups');
            case 'user_save':
                $id = (int)post('id');
                $name = post('username');
                $pass = (string)($_POST['password'] ?? '');
                if (!preg_match('/^[A-Za-z0-9._@-]{3,64}$/', $name)) {
                    throw new RuntimeException('Username non valido (3-64 caratteri: lettere, numeri, . _ @ -)');
                }
                if (($pass !== '' || !$id) && strlen($pass) < 12) {
                    throw new RuntimeException('La password deve avere almeno 12 caratteri');
                }
                $gui = chk('can_gui');
                $active = chk('active');
                if ($id === $me['id'] && (!$gui || !$active)) {
                    throw new RuntimeException('Non puoi togliere a te stesso l\'accesso alla GUI');
                }
                if ($id) {
                    q('UPDATE dba_users SET username=?, can_gui=?, can_mcp=?, can_write=?, active=? WHERE id=?', [$name, $gui, chk('can_mcp'), chk('can_write'), $active, $id]);
                    if ($pass !== '') {
                        q('UPDATE dba_users SET password_hash=? WHERE id=?', [password_hash($pass, PASSWORD_DEFAULT), $id]);
                        q('DELETE FROM dba_mcp_sessions WHERE user_id = ?', [$id]);
                    }
                } else {
                    q('INSERT INTO dba_users (username, password_hash, can_gui, can_mcp, can_write, active) VALUES (?,?,?,?,?,?)',
                        [$name, password_hash($pass, PASSWORD_DEFAULT), $gui, chk('can_mcp'), chk('can_write'), $active]);
                }
                audit('gui', $un, $id ? 'user_update' : 'user_create', null, $name);
                flash('success', "Utente «{$name}» salvato");
                go('users');
            case 'user_delete':
                $id = (int)post('id');
                if ($id === $me['id']) {
                    throw new RuntimeException('Non puoi eliminare il tuo utente');
                }
                q('DELETE FROM dba_mcp_sessions WHERE user_id = ?', [$id]);
                q('DELETE FROM dba_users WHERE id = ?', [$id]);
                audit('gui', $un, 'user_delete', null, (string)$id);
                flash('success', 'Utente eliminato');
                go('users');
            case 'user_unlock':
                q('DELETE FROM dba_login_attempts WHERE username = ? AND ok = 0', [post('username')]);
                flash('success', 'Blocco rimosso');
                go('users');
            case 's3_save':
            case 's3_test':
                foreach (['s3_endpoint', 's3_region', 's3_bucket', 's3_access_key', 's3_prefix'] as $k) {
                    setting_set($k, post($k));
                }
                setting_set('s3_path_style', (string)chk('s3_path_style'));
                setting_set('s3_sse', (string)chk('s3_sse'));
                setting_set('s3_retention_days', (string)max(0, (int)post('s3_retention_days', '30')));
                if (($_POST['s3_secret'] ?? '') !== '') {
                    setting_set('s3_secret_enc', enc((string)$_POST['s3_secret']));
                }
                audit('gui', $un, 's3_save');
                if ($act === 's3_test') {
                    (new S3(s3_config()))->selfTest();
                    flash('success', 'Test S3 riuscito: scrittura e cancellazione di un oggetto di prova completate');
                } else {
                    flash('success', 'Impostazioni S3 salvate');
                }
                go('s3');
            case 'mcp_revoke':
                q('DELETE FROM dba_mcp_sessions WHERE token_hash = ?', [post('token_hash')]);
                audit('gui', $un, 'mcp_revoke');
                flash('success', 'Sessione MCP revocata');
                go('mcp');
            case 'mcp_revoke_all':
                q('DELETE FROM dba_mcp_sessions');
                audit('gui', $un, 'mcp_revoke_all');
                flash('success', 'Tutte le sessioni MCP sono state revocate');
                go('mcp');
        }
    } catch (PDOException $e) {
        flash('danger', $e->getCode() === '23000' ? 'Nome già esistente' : 'Errore database: ' . $e->getMessage());
    } catch (Throwable $e) {
        flash('danger', $e->getMessage());
    }
    go($page);
}

// ---------------- vista ----------------
$nav = [
    'dashboard'   => ['dashboard', 'Dashboard'],
    'connections' => ['storage', 'Connessioni'],
    'users'       => ['group', 'Utenti'],
    's3'          => ['cloud_upload', 'Backup S3'],
    'backups'     => ['history', 'Storico backup'],
    'mcp'         => ['hub', 'Server MCP'],
    'audit'       => ['fact_check', 'Audit'],
];
if ($me && !isset($nav[$page])) {
    $page = 'dashboard';
}
$flash = $_SESSION['flash'] ?? [];
unset($_SESSION['flash']);
$csrf = '<input type="hidden" name="csrf" value="' . h($_SESSION['csrf']) . '">';
$icon = fn(string $n, string $cls = '') => '<span class="material-icons-round ' . $cls . '">' . $n . '</span>';
$badge = fn(bool $on, string $yes = 'Sì', string $no = 'No') => '<span class="badge ' . ($on ? 'text-bg-success' : 'text-bg-secondary') . '">' . ($on ? $yes : $no) . '</span>';
$baseUrl = (is_https() ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/');
?><!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title><?= h(APP_NAME) ?></title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
  <link href="assets/app.css" rel="stylesheet">
</head>
<body class="bg-body-tertiary">
<?php if (!$me): ?>
<main class="d-flex align-items-center justify-content-center min-vh-100 p-3">
  <form method="post" class="card shadow-sm login-card" autocomplete="off">
    <div class="card-body p-4">
      <div class="text-center mb-4">
        <?= $icon('admin_panel_settings', 'brand-icon text-primary') ?>
        <h1 class="h4 mt-2 mb-0"><?= h(APP_NAME) ?></h1>
        <div class="text-secondary small">Accesso amministratore</div>
      </div>
      <?php foreach ($flash as [$t, $m]): ?><div class="alert alert-<?= h($t) ?> py-2"><?= h($m) ?></div><?php endforeach; ?>
      <?= $csrf ?><input type="hidden" name="action" value="login">
      <label class="form-label" for="u">Username</label>
      <input class="form-control mb-3" id="u" name="username" required autofocus>
      <label class="form-label" for="pw">Password</label>
      <input class="form-control mb-4" id="pw" name="password" type="password" required>
      <button class="btn btn-primary w-100 d-flex align-items-center justify-content-center gap-2"><?= $icon('login') ?> Accedi</button>
    </div>
  </form>
</main>
<?php else: ?>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top shadow-sm">
  <div class="container-fluid">
    <a class="navbar-brand d-flex align-items-center gap-2" href="?p=dashboard"><?= $icon('admin_panel_settings') ?> <?= h(APP_NAME) ?></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav" aria-label="Menu"><span class="navbar-toggler-icon"></span></button>
    <div class="collapse navbar-collapse" id="nav">
      <ul class="navbar-nav me-auto">
        <?php foreach ($nav as $k => [$ic, $label]): ?>
        <li class="nav-item"><a class="nav-link d-flex align-items-center gap-1 <?= $page === $k ? 'active' : '' ?>" href="?p=<?= $k ?>"><?= $icon($ic, 'md-18') ?> <?= $label ?></a></li>
        <?php endforeach; ?>
      </ul>
      <form method="post" class="d-flex align-items-center gap-2">
        <?= $csrf ?><input type="hidden" name="action" value="logout">
        <span class="navbar-text d-flex align-items-center gap-1"><?= $icon('person', 'md-18') ?> <?= h($me['username']) ?></span>
        <button class="btn btn-outline-light btn-sm d-flex align-items-center gap-1"><?= $icon('logout', 'md-18') ?> Esci</button>
      </form>
    </div>
  </div>
</nav>
<main class="container-fluid py-4 px-lg-4">
<?php foreach ($flash as [$t, $m]): ?>
  <div class="alert alert-<?= h($t) ?> alert-dismissible fade show"><?= h($m) ?><button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Chiudi"></button></div>
<?php endforeach; ?>

<?php if ($page === 'dashboard'):
    $cnt = fn(string $sql) => (int)q($sql)->fetchColumn();
    $cards = [
        ['storage', 'Connessioni', $cnt('SELECT COUNT(*) FROM dba_connections'), 'connections'],
        ['hub', 'Sessioni MCP attive', $cnt('SELECT COUNT(*) FROM dba_mcp_sessions WHERE user_id IS NOT NULL AND last_seen_at > NOW() - INTERVAL ' . (int)(cfg()['mcp']['idle_minutes'] ?? 30) . ' MINUTE'), 'mcp'],
        ['cloud_done', 'Backup riusciti (7 gg)', $cnt("SELECT COUNT(*) FROM dba_backups WHERE status IN ('ok','deleted') AND started_at > NOW() - INTERVAL 7 DAY"), 'backups'],
        ['error', 'Backup falliti (7 gg)', $cnt("SELECT COUNT(*) FROM dba_backups WHERE status = 'error' AND started_at > NOW() - INTERVAL 7 DAY"), 'backups'],
        ['gpp_bad', 'Login falliti (24 h)', $cnt('SELECT COUNT(*) FROM dba_login_attempts WHERE ok = 0 AND created_at > NOW() - INTERVAL 1 DAY'), 'audit'],
    ];
    $noBackup = q("SELECT c.name FROM dba_connections c WHERE c.backup_enabled = 1 AND NOT EXISTS
                   (SELECT 1 FROM dba_backups b WHERE b.connection_id = c.id AND b.status = 'ok' AND b.started_at > NOW() - INTERVAL 2 DAY)")->fetchAll(PDO::FETCH_COLUMN);
?>
  <div class="row g-3 mb-4">
    <?php foreach ($cards as [$ic, $label, $val, $link]): ?>
    <div class="col-6 col-lg">
      <a href="?p=<?= $link ?>" class="card h-100 text-decoration-none shadow-sm"><div class="card-body">
        <div class="d-flex align-items-center gap-2 text-secondary small"><?= $icon($ic, 'md-18') ?> <?= $label ?></div>
        <div class="display-6 fw-semibold"><?= $val ?></div>
      </div></a>
    </div>
    <?php endforeach; ?>
  </div>
  <?php if ($noBackup): ?>
  <div class="alert alert-warning d-flex align-items-center gap-2"><?= $icon('warning') ?>
    <div>Nessun backup riuscito nelle ultime 48 ore per: <strong><?= h(implode(', ', $noBackup)) ?></strong></div></div>
  <?php endif; ?>
  <div class="card shadow-sm"><div class="card-header fw-semibold">Ultime attività</div>
    <div class="table-responsive"><table class="table table-sm table-hover mb-0 align-middle">
      <thead><tr><th>Data</th><th>Utente</th><th>Canale</th><th>Azione</th><th>Connessione</th></tr></thead><tbody>
      <?php foreach (q('SELECT * FROM dba_audit ORDER BY id DESC LIMIT 12') as $a): ?>
      <tr><td class="text-nowrap"><?= h($a['created_at']) ?></td><td><?= h($a['username']) ?></td><td><span class="badge text-bg-light border"><?= h($a['channel']) ?></span></td><td><?= h($a['action']) ?></td><td><?= h($a['conn_name']) ?></td></tr>
      <?php endforeach; ?>
    </tbody></table></div>
  </div>

<?php elseif ($page === 'connections'):
    $rows = conn_all();
    $edit = isset($_GET['edit']) ? ($_GET['edit'] === 'new' ? ['id' => 0, 'name' => '', 'host' => '127.0.0.1', 'port' => 3306, 'db_name' => '', 'db_user' => '', 'use_ssl' => 0, 'allow_write' => 0, 'backup_enabled' => 1, 'notes' => ''] : conn_get((int)$_GET['edit'])) : null;
?>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="h4 mb-0">Connessioni ai database</h1>
    <a class="btn btn-primary d-flex align-items-center gap-1" href="?p=connections&edit=new"><?= $icon('add') ?> Nuova</a>
  </div>
  <?php if ($edit): ?>
  <form method="post" class="card shadow-sm mb-4" autocomplete="off"><div class="card-header fw-semibold"><?= $edit['id'] ? 'Modifica «' . h($edit['name']) . '»' : 'Nuova connessione' ?></div>
    <div class="card-body row g-3">
      <?= $csrf ?><input type="hidden" name="action" value="conn_save"><input type="hidden" name="id" value="<?= (int)$edit['id'] ?>">
      <div class="col-md-3"><label class="form-label">Nome (alias MCP)</label><input class="form-control" name="name" value="<?= h($edit['name']) ?>" required pattern="[a-z0-9][a-z0-9_\-]{1,62}" placeholder="es. gestionale"></div>
      <div class="col-md-4"><label class="form-label">Host</label><input class="form-control" name="host" value="<?= h($edit['host']) ?>" required></div>
      <div class="col-md-2"><label class="form-label">Porta</label><input class="form-control" name="port" type="number" min="1" max="65535" value="<?= (int)$edit['port'] ?>" required></div>
      <div class="col-md-3"><label class="form-label">Database</label><input class="form-control" name="db_name" value="<?= h($edit['db_name']) ?>" required></div>
      <div class="col-md-3"><label class="form-label">Utente MySQL</label><input class="form-control" name="db_user" value="<?= h($edit['db_user']) ?>" required autocomplete="off"></div>
      <div class="col-md-3"><label class="form-label">Password MySQL</label><input class="form-control" name="db_pass" type="password" autocomplete="new-password" <?= $edit['id'] ? 'placeholder="invariata se vuota"' : '' ?>></div>
      <div class="col-md-6"><label class="form-label">Note</label><input class="form-control" name="notes" maxlength="500" value="<?= h($edit['notes']) ?>"></div>
      <div class="col-12 d-flex flex-wrap gap-4">
        <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="ssl" name="use_ssl" <?= $edit['use_ssl'] ? 'checked' : '' ?>><label class="form-check-label" for="ssl">Connessione TLS</label></div>
        <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="aw" name="allow_write" <?= $edit['allow_write'] ? 'checked' : '' ?>><label class="form-check-label" for="aw">Consenti scrittura via MCP (execute_sql)</label></div>
        <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="bk" name="backup_enabled" <?= $edit['backup_enabled'] ? 'checked' : '' ?>><label class="form-check-label" for="bk">Includi nel backup S3 pianificato</label></div>
      </div>
      <div class="col-12 form-text">La password viene salvata cifrata (libsodium). Consigliato un utente MySQL dedicato con i soli privilegi necessari: per le analisi basta <code>SELECT</code> (più <code>SELECT ON mysql.user</code> e <code>PROCESS</code> per l'audit di sicurezza); per il backup servono anche <code>SHOW VIEW, TRIGGER, LOCK TABLES</code>.</div>
    </div>
    <div class="card-footer d-flex gap-2"><button class="btn btn-primary d-flex align-items-center gap-1"><?= $icon('save') ?> Salva</button><a class="btn btn-outline-secondary" href="?p=connections">Annulla</a></div>
  </form>
  <?php endif; ?>
  <div class="card shadow-sm"><div class="table-responsive"><table class="table table-hover mb-0 align-middle">
    <thead><tr><th>Nome</th><th>Server</th><th>Database</th><th>Utente</th><th>Scrittura</th><th>Backup</th><th class="text-end">Azioni</th></tr></thead><tbody>
    <?php if (!$rows): ?><tr><td colspan="7" class="text-center text-secondary py-4">Nessuna connessione registrata</td></tr><?php endif; ?>
    <?php foreach ($rows as $c): ?>
    <tr>
      <td class="fw-semibold"><?= h($c['name']) ?><?php if ($c['notes']): ?><div class="small text-secondary fw-normal"><?= h($c['notes']) ?></div><?php endif; ?></td>
      <td><?= h($c['host']) ?>:<?= (int)$c['port'] ?><?= $c['use_ssl'] ? ' ' . $icon('lock', 'md-18 text-success align-middle') : '' ?></td>
      <td><?= h($c['db_name']) ?></td><td><?= h($c['db_user']) ?></td>
      <td><?= $badge((bool)$c['allow_write'], 'Consentita', 'Sola lettura') ?></td><td><?= $badge((bool)$c['backup_enabled']) ?></td>
      <td class="text-end text-nowrap">
        <form method="post" class="d-inline"><?= $csrf ?><input type="hidden" name="id" value="<?= (int)$c['id'] ?>">
          <button class="btn btn-sm btn-outline-success" name="action" value="conn_test" title="Prova connessione"><?= $icon('power', 'md-18') ?></button>
          <button class="btn btn-sm btn-outline-primary" name="action" value="backup_now" title="Backup su S3 adesso"><?= $icon('cloud_upload', 'md-18') ?></button>
          <a class="btn btn-sm btn-outline-secondary" href="?p=connections&edit=<?= (int)$c['id'] ?>" title="Modifica"><?= $icon('edit', 'md-18') ?></a>
          <button class="btn btn-sm btn-outline-danger js-confirm" name="action" value="conn_delete" data-confirm="Eliminare la connessione «<?= h($c['name']) ?>»?" title="Elimina"><?= $icon('delete', 'md-18') ?></button>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </tbody></table></div></div>

<?php elseif ($page === 'users'):
    $rows = q('SELECT u.*, (SELECT COUNT(*) FROM dba_login_attempts a WHERE a.username = u.username AND a.ok = 0 AND a.created_at > NOW() - INTERVAL ' . (int)(cfg()['security']['lock_minutes'] ?? 15) . ' MINUTE) AS fails FROM dba_users u ORDER BY username')->fetchAll();
    $edit = null;
    if (isset($_GET['edit'])) {
        $edit = $_GET['edit'] === 'new' ? ['id' => 0, 'username' => '', 'can_gui' => 0, 'can_mcp' => 1, 'can_write' => 0, 'active' => 1]
            : q('SELECT * FROM dba_users WHERE id = ?', [(int)$_GET['edit']])->fetch();
    }
    $maxFail = (int)(cfg()['security']['max_failures'] ?? 5);
?>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="h4 mb-0">Utenti</h1>
    <a class="btn btn-primary d-flex align-items-center gap-1" href="?p=users&edit=new"><?= $icon('person_add') ?> Nuovo</a>
  </div>
  <?php if ($edit): ?>
  <form method="post" class="card shadow-sm mb-4" autocomplete="off"><div class="card-header fw-semibold"><?= $edit['id'] ? 'Modifica «' . h($edit['username']) . '»' : 'Nuovo utente' ?></div>
    <div class="card-body row g-3">
      <?= $csrf ?><input type="hidden" name="action" value="user_save"><input type="hidden" name="id" value="<?= (int)$edit['id'] ?>">
      <div class="col-md-4"><label class="form-label">Username</label><input class="form-control" name="username" value="<?= h($edit['username']) ?>" required autocomplete="off"></div>
      <div class="col-md-4"><label class="form-label">Password (min 12 caratteri)</label><input class="form-control" name="password" type="password" minlength="12" autocomplete="new-password" <?= $edit['id'] ? 'placeholder="invariata se vuota"' : 'required' ?>></div>
      <div class="col-12 d-flex flex-wrap gap-4">
        <?php foreach (['active' => 'Attivo', 'can_gui' => 'Accesso GUI', 'can_mcp' => 'Accesso server MCP', 'can_write' => 'Scrittura via MCP'] as $k => $label): ?>
        <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="f_<?= $k ?>" name="<?= $k ?>" <?= $edit[$k] ? 'checked' : '' ?>><label class="form-check-label" for="f_<?= $k ?>"><?= $label ?></label></div>
        <?php endforeach; ?>
      </div>
    </div>
    <div class="card-footer d-flex gap-2"><button class="btn btn-primary d-flex align-items-center gap-1"><?= $icon('save') ?> Salva</button><a class="btn btn-outline-secondary" href="?p=users">Annulla</a></div>
  </form>
  <?php endif; ?>
  <div class="card shadow-sm"><div class="table-responsive"><table class="table table-hover mb-0 align-middle">
    <thead><tr><th>Username</th><th>Stato</th><th>GUI</th><th>MCP</th><th>Scrittura MCP</th><th>Ultimo accesso</th><th class="text-end">Azioni</th></tr></thead><tbody>
    <?php foreach ($rows as $u): ?>
    <tr>
      <td class="fw-semibold"><?= h($u['username']) ?></td>
      <td><?= $u['fails'] >= $maxFail ? '<span class="badge text-bg-danger">Bloccato</span>' : $badge((bool)$u['active'], 'Attivo', 'Disattivo') ?></td>
      <td><?= $badge((bool)$u['can_gui']) ?></td><td><?= $badge((bool)$u['can_mcp']) ?></td><td><?= $badge((bool)$u['can_write']) ?></td>
      <td class="text-nowrap"><?= h($u['last_login_at'] ?? '—') ?></td>
      <td class="text-end text-nowrap">
        <form method="post" class="d-inline"><?= $csrf ?><input type="hidden" name="id" value="<?= (int)$u['id'] ?>"><input type="hidden" name="username" value="<?= h($u['username']) ?>">
          <?php if ($u['fails'] > 0): ?><button class="btn btn-sm btn-outline-warning" name="action" value="user_unlock" title="Azzera tentativi falliti"><?= $icon('lock_open', 'md-18') ?></button><?php endif; ?>
          <a class="btn btn-sm btn-outline-secondary" href="?p=users&edit=<?= (int)$u['id'] ?>" title="Modifica"><?= $icon('edit', 'md-18') ?></a>
          <?php if ((int)$u['id'] !== $me['id']): ?><button class="btn btn-sm btn-outline-danger js-confirm" name="action" value="user_delete" data-confirm="Eliminare l'utente «<?= h($u['username']) ?>»?" title="Elimina"><?= $icon('delete', 'md-18') ?></button><?php endif; ?>
        </form>
      </td>
    </tr>
    <?php endforeach; ?>
  </tbody></table></div></div>

<?php elseif ($page === 's3'):
    $s = fn(string $k, string $d = '') => h(setting($k, $d));
    $hasSecret = (bool)setting('s3_secret_enc');
    $cronLine = '30 2 * * * /usr/bin/php ' . realpath(APP_ROOT . '/bin/backup.php') . ' >> /var/log/dbadmin-backup.log 2>&1';
?>
  <h1 class="h4 mb-3">Backup su cloud S3</h1>
  <div class="row g-4">
    <div class="col-lg-7"><form method="post" class="card shadow-sm" autocomplete="off"><div class="card-header fw-semibold">Destinazione</div>
      <div class="card-body row g-3"><?= $csrf ?>
        <div class="col-md-8"><label class="form-label">Endpoint</label><input class="form-control" name="s3_endpoint" value="<?= $s('s3_endpoint') ?>" placeholder="vuoto = Amazon S3 · es. https://s3.eu-central-1.wasabisys.com"></div>
        <div class="col-md-4"><label class="form-label">Regione</label><input class="form-control" name="s3_region" value="<?= $s('s3_region', 'eu-south-1') ?>" required></div>
        <div class="col-md-6"><label class="form-label">Bucket</label><input class="form-control" name="s3_bucket" value="<?= $s('s3_bucket') ?>" required></div>
        <div class="col-md-6"><label class="form-label">Prefisso (cartella)</label><input class="form-control" name="s3_prefix" value="<?= $s('s3_prefix', 'mysql-backup') ?>"></div>
        <div class="col-md-6"><label class="form-label">Access key</label><input class="form-control" name="s3_access_key" value="<?= $s('s3_access_key') ?>" required autocomplete="off"></div>
        <div class="col-md-6"><label class="form-label">Secret key</label><input class="form-control" name="s3_secret" type="password" autocomplete="new-password" placeholder="<?= $hasSecret ? 'salvata · invariata se vuota' : '' ?>"></div>
        <div class="col-md-4"><label class="form-label">Conserva per (giorni)</label><input class="form-control" name="s3_retention_days" type="number" min="0" value="<?= $s('s3_retention_days', '30') ?>"><div class="form-text">0 = non eliminare mai</div></div>
        <div class="col-md-8 d-flex flex-column justify-content-center gap-2">
          <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="ps" name="s3_path_style" <?= setting('s3_path_style') === '1' ? 'checked' : '' ?>><label class="form-check-label" for="ps">URL path-style (MinIO e alcuni provider compatibili)</label></div>
          <div class="form-check form-switch"><input class="form-check-input" type="checkbox" id="sse" name="s3_sse" <?= setting('s3_sse') === '1' ? 'checked' : '' ?>><label class="form-check-label" for="sse">Cifratura lato server (SSE-S3 / AES256)</label></div>
        </div>
      </div>
      <div class="card-footer d-flex gap-2">
        <button class="btn btn-primary d-flex align-items-center gap-1" name="action" value="s3_save"><?= $icon('save') ?> Salva</button>
        <button class="btn btn-outline-success d-flex align-items-center gap-1" name="action" value="s3_test"><?= $icon('cloud_sync') ?> Salva e prova</button>
      </div>
    </form></div>
    <div class="col-lg-5"><div class="card shadow-sm"><div class="card-header fw-semibold">Pianificazione (cron)</div><div class="card-body">
      <p>Il backup pianificato salva tutte le connessioni con «Includi nel backup S3» attivo. Aggiungere al crontab (oppure in Webmin → Sistema → Scheduled Cron Jobs):</p>
      <pre class="bg-dark text-light p-3 rounded small mb-3"><code><?= h($cronLine) ?></code></pre>
      <ul class="small text-secondary mb-0">
        <li>File su S3: <code>prefisso/nome/nome_AAAAMMGG_HHMMSS.sql.gz</code></li>
        <li>La chiave S3 dovrebbe poter fare solo <code>PutObject</code> e <code>DeleteObject</code> sul bucket di backup.</li>
        <li>I backup più vecchi dei giorni indicati vengono eliminati dopo ogni backup riuscito.</li>
      </ul>
    </div></div></div>
  </div>

<?php elseif ($page === 'backups'): ?>
  <h1 class="h4 mb-3">Storico backup</h1>
  <div class="card shadow-sm"><div class="table-responsive"><table class="table table-sm table-hover mb-0 align-middle">
    <thead><tr><th>Inizio</th><th>Connessione</th><th>Origine</th><th>Esito</th><th>Dimensione</th><th>Durata</th><th>Oggetto S3 / messaggio</th></tr></thead><tbody>
    <?php $bk = Backup::history(null, 200); if (!$bk): ?><tr><td colspan="7" class="text-center text-secondary py-4">Nessun backup eseguito</td></tr><?php endif; ?>
    <?php foreach ($bk as $b):
        $cls = ['ok' => 'success', 'error' => 'danger', 'running' => 'warning', 'deleted' => 'secondary'][$b['status']];
        $lab = ['ok' => 'Riuscito', 'error' => 'Errore', 'running' => 'In corso', 'deleted' => 'Scaduto (rimosso)'][$b['status']];
        $dur = $b['finished_at'] ? (strtotime($b['finished_at']) - strtotime($b['started_at'])) . ' s' : '—'; ?>
    <tr><td class="text-nowrap"><?= h($b['started_at']) ?></td><td class="fw-semibold"><?= h($b['conn_name']) ?></td><td><?= h($b['trigger_by']) ?></td>
      <td><span class="badge text-bg-<?= $cls ?>"><?= $lab ?></span></td><td class="text-nowrap"><?= h(human_bytes($b['size_bytes'] === null ? null : (int)$b['size_bytes'])) ?></td><td><?= h($dur) ?></td>
      <td class="small text-break"><?= h($b['status'] === 'error' ? $b['message'] : $b['s3_key']) ?></td></tr>
    <?php endforeach; ?>
  </tbody></table></div></div>

<?php elseif ($page === 'mcp'):
    $url = $baseUrl . '/mcp.php';
    $sess = q('SELECT s.*, u.username FROM dba_mcp_sessions s LEFT JOIN dba_users u ON u.id = s.user_id ORDER BY s.last_seen_at DESC')->fetchAll();
    $mc = cfg()['mcp'] ?? [];
?>
  <h1 class="h4 mb-3">Server MCP</h1>
  <div class="row g-4">
    <div class="col-lg-6"><div class="card shadow-sm h-100"><div class="card-header fw-semibold">Collegamento</div><div class="card-body">
      <label class="form-label">Endpoint (Streamable HTTP)</label>
      <input class="form-control font-monospace mb-3" readonly value="<?= h($url) ?>">
      <p class="mb-1 fw-semibold">Claude Code</p>
      <pre class="bg-dark text-light p-3 rounded small"><code>claude mcp add --transport http dbadmin <?= h($url) ?></code></pre>
      <p class="mb-1 fw-semibold">Claude Desktop / claude.ai</p>
      <p class="small text-secondary">Impostazioni → Connettori → Aggiungi connettore personalizzato, incollando l'endpoint (senza OAuth).</p>
      <div class="alert alert-info small mb-0 d-flex gap-2"><?= $icon('info') ?><div>Ogni sessione parte <strong>bloccata</strong>: l'assistente deve chiamare il tool <code>login</code> con username e password di un utente con «Accesso server MCP». La sessione scade dopo <?= (int)($mc['idle_minutes'] ?? 30) ?> minuti di inattività (massimo <?= (int)($mc['max_hours'] ?? 8) ?> ore). In alternativa il client può inviare <code>Authorization: Basic</code> alla connessione, così la password non passa dalla chat.</div></div>
    </div></div></div>
    <div class="col-lg-6"><div class="card shadow-sm h-100"><div class="card-header fw-semibold">Tool disponibili</div>
      <ul class="list-group list-group-flush small tool-list">
        <?php foreach (McpServer::tools() as $t): ?>
        <li class="list-group-item"><code><?= h($t['name']) ?></code> <?= empty($t['annotations']['readOnlyHint']) ? '<span class="badge text-bg-warning">scrittura</span>' : '' ?><div class="text-secondary"><?= h($t['description']) ?></div></li>
        <?php endforeach; ?>
      </ul>
    </div></div>
    <div class="col-12"><div class="card shadow-sm"><div class="card-header fw-semibold d-flex justify-content-between align-items-center">Sessioni
      <form method="post"><?= $csrf ?><button class="btn btn-sm btn-outline-danger js-confirm" name="action" value="mcp_revoke_all" data-confirm="Revocare tutte le sessioni MCP?">Revoca tutte</button></form></div>
      <div class="table-responsive"><table class="table table-sm table-hover mb-0 align-middle">
        <thead><tr><th>Utente</th><th>Client</th><th>IP</th><th>Creata</th><th>Ultima attività</th><th></th></tr></thead><tbody>
        <?php if (!$sess): ?><tr><td colspan="6" class="text-center text-secondary py-4">Nessuna sessione</td></tr><?php endif; ?>
        <?php foreach ($sess as $x): ?>
        <tr><td><?= $x['username'] ? h($x['username']) : '<span class="badge text-bg-secondary">non autenticata</span>' ?></td><td><?= h($x['client_info']) ?></td><td><?= h($x['ip']) ?></td>
          <td class="text-nowrap"><?= h($x['created_at']) ?></td><td class="text-nowrap"><?= h($x['last_seen_at']) ?></td>
          <td class="text-end"><form method="post"><?= $csrf ?><input type="hidden" name="token_hash" value="<?= h($x['token_hash']) ?>"><button class="btn btn-sm btn-outline-danger" name="action" value="mcp_revoke" title="Revoca"><?= $icon('block', 'md-18') ?></button></form></td></tr>
        <?php endforeach; ?>
      </tbody></table></div>
    </div></div>
  </div>

<?php elseif ($page === 'audit'):
    $ch = in_array($_GET['channel'] ?? '', ['gui', 'mcp', 'cron'], true) ? $_GET['channel'] : '';
    $rows = $ch ? q('SELECT * FROM dba_audit WHERE channel = ? ORDER BY id DESC LIMIT 300', [$ch]) : q('SELECT * FROM dba_audit ORDER BY id DESC LIMIT 300');
?>
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h1 class="h4 mb-0">Audit</h1>
    <div class="btn-group btn-group-sm">
      <?php foreach (['' => 'Tutti', 'gui' => 'GUI', 'mcp' => 'MCP', 'cron' => 'Backup'] as $k => $label): ?>
      <a class="btn btn-outline-secondary <?= $ch === $k ? 'active' : '' ?>" href="?p=audit<?= $k ? '&channel=' . $k : '' ?>"><?= $label ?></a>
      <?php endforeach; ?>
    </div>
  </div>
  <div class="card shadow-sm"><div class="table-responsive"><table class="table table-sm table-hover mb-0 align-middle">
    <thead><tr><th>Data</th><th>Utente</th><th>Canale</th><th>Azione</th><th>Connessione</th><th>Dettaglio</th><th>IP</th></tr></thead><tbody>
    <?php foreach ($rows as $a): ?>
    <tr><td class="text-nowrap"><?= h($a['created_at']) ?></td><td><?= h($a['username']) ?></td><td><span class="badge text-bg-light border"><?= h($a['channel']) ?></span></td>
      <td><?= h($a['action']) ?></td><td><?= h($a['conn_name']) ?></td><td class="small font-monospace text-break"><?= h(mb_substr((string)$a['detail'], 0, 400)) ?></td><td><?= h($a['ip']) ?></td></tr>
    <?php endforeach; ?>
  </tbody></table></div></div>
<?php endif; ?>
</main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="assets/app.js"></script>
<?php endif; ?>
</body>
</html>

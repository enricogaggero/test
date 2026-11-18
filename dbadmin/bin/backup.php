#!/usr/bin/env php
<?php
declare(strict_types=1);
// Backup su S3 dei database registrati.
//   php bin/backup.php                    tutte le connessioni con "Backup S3" attivo (uso da cron)
//   php bin/backup.php --connection=NOME  una sola connessione (nome o id), anche se non abilitata al cron
// Cron di esempio (ogni notte alle 02:30):
//   30 2 * * * /usr/bin/php /percorso/dbadmin/bin/backup.php >> /var/log/dbadmin-backup.log 2>&1

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Solo CLI');
}
require __DIR__ . '/../src/bootstrap.php';

$opt = getopt('', ['connection:', 'trigger:']);
$trigger = preg_replace('/[^a-z]/', '', (string)($opt['trigger'] ?? 'cron')) ?: 'cron';

try {
    $conns = isset($opt['connection'])
        ? [conn_get((string)$opt['connection'])]
        : array_values(array_filter(conn_all(), fn($c) => $c['backup_enabled']));
} catch (Throwable $e) {
    fwrite(STDERR, date('c') . ' ERRORE: ' . $e->getMessage() . "\n");
    exit(2);
}
if (!$conns) {
    echo date('c') . " Nessuna connessione con backup attivo.\n";
    exit(0);
}

// un solo backup alla volta per connessione (evita sovrapposizioni tra cron e avvii manuali)
$failed = 0;
foreach ($conns as $c) {
    $lock = fopen(sys_get_temp_dir() . '/dbadmin_backup_' . $c['id'] . '.lock', 'c');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
        echo date('c') . " {$c['name']}: backup gia' in corso, salto.\n";
        continue;
    }
    $r = Backup::run($c, $trigger);
    flock($lock, LOCK_UN);
    fclose($lock);
    if ($r['status'] === 'ok') {
        echo date('c') . " {$c['name']}: OK {$r['s3_key']} (" . human_bytes((int)$r['size_bytes']) . ")\n";
    } else {
        $failed++;
        fwrite(STDERR, date('c') . " {$c['name']}: ERRORE {$r['message']}\n");
    }
}
exit($failed ? 1 : 0);

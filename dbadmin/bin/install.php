#!/usr/bin/env php
<?php
declare(strict_types=1);
// Installazione:
//   php bin/install.php --genkey                       genera una app_key da incollare in config.php
//   php bin/install.php                                crea/aggiorna le tabelle e l'utente amministratore (interattivo)
//   php bin/install.php --user=admin --password=...    come sopra, non interattivo

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Solo CLI');
}
$opt = getopt('', ['genkey', 'user:', 'password:']);
if (isset($opt['genkey'])) {
    echo base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES)) . "\n";
    exit(0);
}

require __DIR__ . '/../src/bootstrap.php';

try {
    app_key();
    foreach (array_filter(array_map('trim', explode(';', (string)file_get_contents(APP_ROOT . '/sql/schema.sql')))) as $sql) {
        // toglie le righe di solo commento in testa all'istruzione
        $sql = trim((string)preg_replace('/^\s*--.*$/m', '', $sql));
        if ($sql !== '') {
            appdb()->exec($sql);
        }
    }
    echo "Tabelle create/verificate.\n";

    $user = $opt['user'] ?? null;
    $pass = $opt['password'] ?? null;
    if ($user === null) {
        $user = trim((string)readline('Username amministratore [admin]: ')) ?: 'admin';
    }
    if ($pass === null) {
        echo 'Password (min 12 caratteri): ';
        shell_exec('stty -echo 2>/dev/null');
        $pass = rtrim((string)fgets(STDIN), "\r\n");
        shell_exec('stty echo 2>/dev/null');
        echo "\n";
    }
    if (strlen($pass) < 12) {
        throw new RuntimeException('Password troppo corta: minimo 12 caratteri');
    }
    q('INSERT INTO dba_users (username, password_hash, can_gui, can_mcp, can_write, active) VALUES (?,?,1,1,1,1)
       ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), can_gui = 1, active = 1',
        [$user, password_hash($pass, PASSWORD_DEFAULT)]);
    q('DELETE FROM dba_login_attempts WHERE username = ?', [$user]);
    echo "Utente '$user' pronto (GUI + MCP + scrittura).\n";
} catch (Throwable $e) {
    fwrite(STDERR, 'ERRORE: ' . $e->getMessage() . "\n");
    exit(1);
}

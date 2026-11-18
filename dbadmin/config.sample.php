<?php
// Copiare in config.php (fuori dal controllo versione, permessi 600) e compilare.
return [
    // Database applicativo (utenti, credenziali cifrate, audit, log backup)
    'db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => 'dbadmin',
        'user'    => 'dbadmin',
        'pass'    => 'password',
        'charset' => 'utf8mb4',
    ],

    // Chiave di cifratura delle password dei DB registrati (32 byte in base64).
    // Generarla con:  php bin/install.php --genkey
    // ATTENZIONE: se la perdi, le credenziali salvate non sono piu' leggibili.
    'app_key' => '',

    'security' => [
        'require_https'  => true,   // rifiuta GUI e MCP su HTTP in chiaro
        'trust_proxy'    => false,  // true solo dietro reverse proxy (usa X-Forwarded-*)
        'max_failures'   => 5,      // tentativi di login falliti prima del blocco
        'lock_minutes'   => 15,     // durata del blocco (per utente e per IP)
        'allowed_ips'    => [],     // [] = tutti; es. ['203.0.113.10'] (vale per GUI e MCP)
    ],

    'mcp' => [
        'idle_minutes'   => 30,     // la sessione MCP scade dopo N minuti di inattivita'
        'max_hours'      => 8,      // durata massima assoluta di una sessione
        'max_rows'       => 200,    // righe restituite di default da run_query
        'query_timeout'  => 30,     // secondi massimi per le query in sola lettura
    ],

    'backup' => [
        'tmp_dir'        => '',             // '' = sys_get_temp_dir(); serve spazio per il dump .gz
        'mysqldump_bin'  => 'mysqldump',    // oppure 'mariadb-dump'
        'dump_args'      => '--single-transaction --quick --routines --triggers --no-tablespaces',
        'php_bin'        => 'php',          // usato per lanciare i backup manuali in background
    ],
];

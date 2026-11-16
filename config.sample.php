<?php
// Copiare in config.php (fuori dal controllo versione) e compilare.
return [
    'db' => [
        'host'    => '127.0.0.1',
        'port'    => 3306,
        'name'    => 'egauto',
        'user'    => 'utente',
        'pass'    => 'password',
        'charset' => 'utf8mb4',
    ],

    // Mappatura tabella/colonne di EG Auto (adattare ai nomi reali)
    'egauto' => [
        'table'     => 'veicoli',
        'id_col'    => 'id',
        'plate_col' => 'targa',
        // colonne descrittive mostrate in scheda (opzionali, devono esistere)
        'info_cols' => ['marca', 'modello'],
    ],

    // Accesso all'app: password condivisa (cambiarla!)
    'app_password' => 'cambiami',

    'google_maps_key' => 'INSERISCI_API_KEY_GOOGLE_MAPS',

    'telegram' => [
        'enabled'        => false,
        'bot_token'      => '123456:ABC...',
        'webhook_secret' => 'stringa-casuale-lunga',   // secret_token di setWebhook
        'allowed_chats'  => [],                         // [] = nessuno; es. [123456789]
    ],
];

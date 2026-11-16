# EG Auto · Posizione veicolo

Web app mobile-first (PHP 8.1+, MySQL, Bootstrap 5, icone Material, Google Maps).

1. Inserisci la targa → scheda veicolo letta dal DB MySQL di EG Auto
2. Posizione GPS presa dal dispositivo (browser, richiede **HTTPS**) **oppure** inviata via **Telegram**
3. Lat/Lng salvate nei nuovi campi di EG Auto e mostrate su Google Maps

## Installazione
1. `sql/01_egauto_gps.sql` — adattare il nome tabella ed eseguire (colonne nuove, nullable: non impatta EG Auto esistente)
2. `cp config.sample.php config.php` e compilare (DB, nomi tabella/colonne, password, chiave Google Maps)
3. Document root del web server = cartella `public/` (`config.php` e `src/` restano fuori)
4. Google Cloud: abilitare *Maps JavaScript API* e limitare la chiave per referrer HTTP al tuo dominio
5. Telegram (opzionale): creare il bot con @BotFather, impostare `telegram.enabled`, `bot_token`, `webhook_secret`, `allowed_chats`, poi:
   `https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://TUO-DOMINIO/telegram/webhook.php&secret_token=<webhook_secret>`
   Uso: scrivere la targa al bot → toccare «Invia posizione» (oppure inviare la posizione con la targa come didascalia).

## API (sessione + header `X-CSRF-Token` per POST)
- `GET  /api/vehicle.php?plate=AB123CD`
- `POST /api/position.php` `{"plate":"AB123CD","lat":45.1,"lng":9.2,"accuracy":12}`

## Campi aggiunti a EG Auto
`gps_lat`, `gps_lng`, `gps_accuracy_m`, `gps_source`, `gps_updated_at` + tabella di servizio `gps_telegram_state`.

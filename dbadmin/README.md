# DB Admin MCP

Console web + server MCP per amministrare i database MySQL/MariaDB di una VPS
(PHP 8.1+, MySQL, Bootstrap 5, icone Material — nessuna dipendenza Composer).

- **GUI** (`public/index.php`): registra le credenziali di ogni database (cifrate con libsodium), utenti, destinazione S3, storico backup, sessioni MCP, audit.
- **Server MCP** (`public/mcp.php`, Streamable HTTP): ogni sessione nasce **bloccata** e si sblocca solo dopo la validazione user/password.
- **Backup S3** (`bin/backup.php`): `mysqldump | gzip` → S3 o compatibile (Wasabi, Backblaze B2, MinIO…), con retention; pensato per cron.

## Installazione

Requisiti: estensioni PHP `pdo_mysql`, `sodium`, `curl`, `mbstring`; `mysqldump` e `gzip` per i backup.

```bash
# 1. database applicativo (anche da phpMyAdmin)
mysql -e "CREATE DATABASE dbadmin CHARACTER SET utf8mb4;
          CREATE USER 'dbadmin'@'localhost' IDENTIFIED BY '<password>';
          GRANT ALL ON dbadmin.* TO 'dbadmin'@'localhost';"

# 2. configurazione
cp config.sample.php config.php && chmod 600 config.php
php bin/install.php --genkey        # incollare il risultato in 'app_key'
# compilare la sezione 'db' di config.php

# 3. tabelle + utente amministratore
php bin/install.php
```

4. Web server: creare un virtual host **HTTPS** (es. `dbadmin.tuodominio.it`, da Webmin → Apache → Create virtual host + Let's Encrypt)
   con document root = `dbadmin/public/`. `config.php`, `src/`, `bin/`, `sql/` restano fuori dalla web root.
   Il file `config.php` deve essere leggibile dall'utente del web server e da quello del cron.
5. Entrare nella GUI, registrare le connessioni (pulsante «Prova connessione») e configurare «Backup S3».

Fare una copia sicura di `app_key`: senza quella chiave le password salvate non sono recuperabili.

## Server MCP

Endpoint: `https://dbadmin.tuodominio.it/mcp.php`

```bash
# Claude Code – login tramite tool (l'assistente chiede user e password a ogni sessione)
claude mcp add --transport http dbadmin https://dbadmin.tuodominio.it/mcp.php

# in alternativa: credenziali nell'header, la password non passa dalla chat
claude mcp add --transport http dbadmin https://dbadmin.tuodominio.it/mcp.php \
  --header "Authorization: Basic $(printf 'utente:password' | base64)"
```

Su Claude Desktop / claude.ai: Impostazioni → Connettori → connettore personalizzato con lo stesso URL.

Sessione: scade dopo 30 minuti di inattività (max 8 ore), revocabile dalla GUI; 5 login falliti bloccano utente e IP per 15 minuti
(valori in `config.php`). Con `security.allowed_ips` si può limitare l'accesso a IP noti.

| Tool | Cosa fa |
|---|---|
| `login` / `logout` | sblocca / chiude la sessione |
| `list_connections`, `server_info`, `list_tables`, `describe_table`, `process_list` | inventario e struttura |
| `run_query`, `explain_query` | una query in sola lettura (transazione `READ ONLY`, timeout, limite righe) |
| `execute_sql` | aggiornamenti (DML/DDL): anteprima, poi `confirm=true`; serve utente con «Scrittura via MCP» **e** connessione con «Consenti scrittura» |
| `unused_objects` | tabelle mai lette/scritte, indici mai usati, tabelle vuote |
| `column_usage` | campi sempre NULL / vuoti / costanti / valorizzati in meno dell'1% delle righe |
| `performance_report` | metriche server, query più costose, full scan, tabelle senza PK, indici ridondanti, frammentazione, raccomandazioni |
| `security_audit` | account deboli, root remoto, host `%`, privilegi globali, TLS, `local_infile`, `secure_file_priv`, ecc. |
| `backup_status`, `backup_now` | storico e avvio manuale del backup S3 |

`execute_sql` rifiuta sempre gestione utenti/privilegi, `DROP DATABASE` e accesso a file. Ogni query e ogni modifica finisce nell'audit.

### Privilegi MySQL consigliati per l'utente di ogni connessione

```sql
GRANT SELECT, SHOW VIEW, TRIGGER, LOCK TABLES ON miodb.* TO 'mcp_miodb'@'localhost';  -- analisi + backup
GRANT SELECT ON performance_schema.* TO 'mcp_miodb'@'localhost';   -- statistiche di utilizzo e query lente
GRANT SELECT ON mysql.user TO 'mcp_miodb'@'localhost';             -- audit degli account
GRANT PROCESS ON *.* TO 'mcp_miodb'@'localhost';                   -- process list completa (facoltativo)
-- solo se si vuole usare execute_sql:
GRANT INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP ON miodb.* TO 'mcp_miodb'@'localhost';
```

Le statistiche «mai usato» richiedono `performance_schema=ON` (default su MySQL, **spento di default su MariaDB**: aggiungerlo a `my.cnf` e riavviare)
e contano dall'ultimo riavvio del server.

## Backup pianificato

```cron
30 2 * * * /usr/bin/php /percorso/dbadmin/bin/backup.php >> /var/log/dbadmin-backup.log 2>&1
```

Da Webmin: Sistema → Scheduled Cron Jobs. Salva tutte le connessioni con «Includi nel backup S3 pianificato»;
`--connection=NOME` per una sola. Oggetti: `prefisso/nome/nome_AAAAMMGG_HHMMSS.sql.gz`. Exit code ≠ 0 se almeno un backup fallisce.

- Limite: 5 GB per dump compresso (singolo PUT S3).
- La chiave S3 dovrebbe avere solo `s3:PutObject` e `s3:DeleteObject` sul bucket di backup.
- Ripristino: `aws s3 cp s3://bucket/chiave - | gunzip | mysql miodb`.

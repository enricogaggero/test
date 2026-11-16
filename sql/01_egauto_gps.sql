-- EG Auto: campi per la posizione GPS del veicolo.
-- Modifica SOLO ADDITIVA: colonne nuove, NULL di default. Le query/applicativi
-- esistenti di EG Auto non vengono toccati (nessuna colonna rinominata/rimossa).
-- Sostituire `veicoli` con il nome reale della tabella.
-- Eseguire UNA sola volta (MySQL non supporta ADD COLUMN IF NOT EXISTS).

ALTER TABLE `veicoli`
  ADD COLUMN `gps_lat`        DECIMAL(10,7) NULL DEFAULT NULL COMMENT 'Latitudine WGS84',
  ADD COLUMN `gps_lng`        DECIMAL(10,7) NULL DEFAULT NULL COMMENT 'Longitudine WGS84',
  ADD COLUMN `gps_accuracy_m` FLOAT         NULL DEFAULT NULL COMMENT 'Precisione in metri',
  ADD COLUMN `gps_source`     VARCHAR(20)   NULL DEFAULT NULL COMMENT 'web | telegram',
  ADD COLUMN `gps_updated_at` DATETIME      NULL DEFAULT NULL COMMENT 'Ultimo aggiornamento posizione';

-- Stato conversazione Telegram (tabella separata, non tocca EG Auto)
CREATE TABLE IF NOT EXISTS `gps_telegram_state` (
  `chat_id`    BIGINT       NOT NULL PRIMARY KEY,
  `plate`      VARCHAR(20)  NOT NULL,
  `updated_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

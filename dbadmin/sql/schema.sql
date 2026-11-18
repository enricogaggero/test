-- DB Admin MCP · schema del database applicativo (eseguito da bin/install.php)
CREATE TABLE IF NOT EXISTS dba_users (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(64)  NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  can_gui       TINYINT(1) NOT NULL DEFAULT 0,  -- accesso alla GUI di amministrazione
  can_mcp       TINYINT(1) NOT NULL DEFAULT 1,  -- accesso al server MCP
  can_write     TINYINT(1) NOT NULL DEFAULT 0,  -- puo' usare execute_sql via MCP
  active        TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dba_connections (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name           VARCHAR(64)  NOT NULL UNIQUE,   -- alias usato dai tool MCP
  host           VARCHAR(255) NOT NULL DEFAULT '127.0.0.1',
  port           SMALLINT UNSIGNED NOT NULL DEFAULT 3306,
  db_name        VARCHAR(64)  NOT NULL,
  db_user        VARCHAR(128) NOT NULL,
  db_pass_enc    TEXT NOT NULL,                  -- cifrata (libsodium secretbox)
  use_ssl        TINYINT(1) NOT NULL DEFAULT 0,
  allow_write    TINYINT(1) NOT NULL DEFAULT 0,  -- abilita execute_sql su questo DB
  backup_enabled TINYINT(1) NOT NULL DEFAULT 0,  -- incluso nel cron di backup S3
  notes          VARCHAR(500) NULL,
  created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dba_settings (
  k VARCHAR(64) PRIMARY KEY,
  v TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dba_mcp_sessions (
  token_hash   CHAR(64) PRIMARY KEY,             -- sha256 del Mcp-Session-Id
  user_id      INT UNSIGNED NULL,                -- NULL = sessione non ancora autenticata
  ip           VARCHAR(45) NOT NULL,
  client_info  VARCHAR(255) NULL,
  created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY k_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dba_login_attempts (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username   VARCHAR(64) NOT NULL,
  ip         VARCHAR(45) NOT NULL,
  ok         TINYINT(1) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY k_user (username, created_at),
  KEY k_ip (ip, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dba_audit (
  id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  username   VARCHAR(64) NULL,
  channel    ENUM('gui','mcp','cron') NOT NULL,
  action     VARCHAR(64) NOT NULL,
  conn_name  VARCHAR(64) NULL,
  detail     TEXT NULL,
  ip         VARCHAR(45) NULL,
  KEY k_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS dba_backups (
  id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  connection_id INT UNSIGNED NOT NULL,
  conn_name     VARCHAR(64) NOT NULL,
  trigger_by    VARCHAR(16) NOT NULL,            -- cron | gui | mcp
  started_at    DATETIME NOT NULL,
  finished_at   DATETIME NULL,
  status        ENUM('running','ok','error','deleted') NOT NULL DEFAULT 'running',
  size_bytes    BIGINT UNSIGNED NULL,
  s3_key        VARCHAR(500) NULL,
  message       TEXT NULL,
  KEY k_conn (connection_id, started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

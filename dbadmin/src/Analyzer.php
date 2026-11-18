<?php
declare(strict_types=1);

/** Analisi statistiche, di performance e di sicurezza su un database registrato. */
final class Analyzer
{
    public function __construct(private PDO $pdo)
    {
    }

    private function all(string $sql, array $p = []): array
    {
        return TargetDb::all($this->pdo, $sql, $p);
    }

    private function tryAll(string $sql, array $p = []): ?array
    {
        return TargetDb::tryAll($this->pdo, $sql, $p);
    }

    private function perfSchemaOn(): bool
    {
        $r = $this->tryAll('SELECT @@performance_schema AS v');
        return $r !== null && (int)$r[0]['v'] === 1;
    }

    public function serverInfo(): array
    {
        $v = TargetDb::pairs($this->pdo, "SHOW GLOBAL VARIABLES WHERE Variable_name IN
            ('version','version_comment','innodb_buffer_pool_size','max_connections','character_set_server',
             'collation_server','sql_mode','time_zone','datadir','performance_schema','slow_query_log','long_query_time')");
        $s = TargetDb::pairs($this->pdo, "SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime','Threads_connected','Questions')");
        $db = $this->all('SELECT DATABASE() AS db, CURRENT_USER() AS user')[0];
        return [
            'database'     => $db['db'],
            'current_user' => $db['user'],
            'uptime_days'  => round(((int)($s['Uptime'] ?? 0)) / 86400, 2),
            'status'       => $s,
            'variables'    => $v,
        ];
    }

    public function listTables(): array
    {
        return $this->all(
            "SELECT TABLE_NAME AS `table`, TABLE_TYPE AS type, ENGINE AS engine, TABLE_ROWS AS rows_estimate,
                    ROUND((DATA_LENGTH + INDEX_LENGTH) / 1048576, 2) AS size_mb,
                    ROUND(DATA_FREE / 1048576, 2) AS free_mb, TABLE_COLLATION AS collation,
                    CREATE_TIME AS created, UPDATE_TIME AS updated, TABLE_COMMENT AS comment
               FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()
              ORDER BY (DATA_LENGTH + INDEX_LENGTH) DESC"
        );
    }

    public function describeTable(string $table): array
    {
        $cols = $this->all(
            "SELECT COLUMN_NAME AS `column`, COLUMN_TYPE AS type, IS_NULLABLE AS nullable, COLUMN_DEFAULT AS `default`,
                    COLUMN_KEY AS `key`, EXTRA AS extra, COLUMN_COMMENT AS comment
               FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION",
            [$table]
        );
        if (!$cols) {
            throw new RuntimeException("Tabella '$table' non trovata");
        }
        $idx = $this->all(
            "SELECT INDEX_NAME AS `index`, NOT NON_UNIQUE AS is_unique, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns,
                    MAX(CARDINALITY) AS cardinality, INDEX_TYPE AS type
               FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
              GROUP BY INDEX_NAME, NON_UNIQUE, INDEX_TYPE",
            [$table]
        );
        $fk = $this->all(
            "SELECT CONSTRAINT_NAME AS name, COLUMN_NAME AS `column`, REFERENCED_TABLE_NAME AS ref_table, REFERENCED_COLUMN_NAME AS ref_column
               FROM information_schema.KEY_COLUMN_USAGE
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND REFERENCED_TABLE_NAME IS NOT NULL",
            [$table]
        );
        $create = $this->tryAll('SHOW CREATE TABLE ' . TargetDb::ident($table));
        return [
            'table'        => $table,
            'columns'      => $cols,
            'indexes'      => $idx,
            'foreign_keys' => $fk,
            'create'       => $create ? (array_values($create[0])[1] ?? null) : null,
        ];
    }

    // ------------------------------------------------------------------
    // Statistiche di utilizzo
    // ------------------------------------------------------------------

    /** Tabelle e indici mai usati dall'ultimo riavvio del server, tabelle vuote. */
    public function unusedObjects(): array
    {
        $uptime = (int)(TargetDb::pairs($this->pdo, "SHOW GLOBAL STATUS LIKE 'Uptime'")['Uptime'] ?? 0);
        $out = [
            'observation_window_days' => round($uptime / 86400, 2),
            'note' => 'I contatori partono dall\'ultimo riavvio del server: con una finestra breve i risultati non sono significativi '
                    . '(valutare almeno un ciclo completo di utilizzo, es. fine mese).',
        ];

        $psReadable = $this->perfSchemaOn()
            && $this->tryAll('SELECT 1 FROM performance_schema.table_io_waits_summary_by_table LIMIT 1') !== null;
        if ($this->perfSchemaOn() && !$psReadable) {
            $out['warning'] = 'performance_schema e\' attivo ma l\'utente della connessione non puo\' leggerlo: '
                            . 'eseguire GRANT SELECT ON performance_schema.* TO <utente> per avere le statistiche di utilizzo.';
        }
        if ($psReadable) {
            $out['source'] = 'performance_schema';
            $out['tables_never_accessed'] = $this->tryAll(
                "SELECT t.TABLE_NAME AS `table`, t.TABLE_ROWS AS rows_estimate,
                        ROUND((t.DATA_LENGTH + t.INDEX_LENGTH) / 1048576, 2) AS size_mb
                   FROM information_schema.TABLES t
                   LEFT JOIN performance_schema.table_io_waits_summary_by_table p
                          ON p.OBJECT_SCHEMA = t.TABLE_SCHEMA AND p.OBJECT_NAME = t.TABLE_NAME
                  WHERE t.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = 'BASE TABLE' AND COALESCE(p.COUNT_STAR, 0) = 0
                  ORDER BY size_mb DESC"
            );
            $out['tables_read_only_never_written'] = $this->tryAll(
                "SELECT OBJECT_NAME AS `table`, COUNT_READ AS read_count
                   FROM performance_schema.table_io_waits_summary_by_table
                  WHERE OBJECT_SCHEMA = DATABASE() AND COUNT_READ > 0 AND COUNT_WRITE = 0 ORDER BY COUNT_READ DESC"
            );
            $out['indexes_never_used'] = $this->tryAll(
                "SELECT p.OBJECT_NAME AS `table`, p.INDEX_NAME AS `index`,
                        (SELECT GROUP_CONCAT(s.COLUMN_NAME ORDER BY s.SEQ_IN_INDEX) FROM information_schema.STATISTICS s
                          WHERE s.TABLE_SCHEMA = p.OBJECT_SCHEMA AND s.TABLE_NAME = p.OBJECT_NAME AND s.INDEX_NAME = p.INDEX_NAME) AS columns
                   FROM performance_schema.table_io_waits_summary_by_index_usage p
                  WHERE p.OBJECT_SCHEMA = DATABASE() AND p.INDEX_NAME IS NOT NULL AND p.INDEX_NAME <> 'PRIMARY' AND p.COUNT_STAR = 0
                  ORDER BY p.OBJECT_NAME, p.INDEX_NAME"
            );
        } elseif (($us = $this->tryAll('SELECT @@userstat AS v')) && (int)$us[0]['v'] === 1) {
            $out['source'] = 'MariaDB userstat';
            $out['tables_never_accessed'] = $this->tryAll(
                "SELECT t.TABLE_NAME AS `table`, t.TABLE_ROWS AS rows_estimate
                   FROM information_schema.TABLES t
                   LEFT JOIN information_schema.TABLE_STATISTICS s ON s.TABLE_SCHEMA = t.TABLE_SCHEMA AND s.TABLE_NAME = t.TABLE_NAME
                  WHERE t.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = 'BASE TABLE' AND s.TABLE_NAME IS NULL"
            );
            $out['indexes_never_used'] = $this->tryAll(
                "SELECT DISTINCT st.TABLE_NAME AS `table`, st.INDEX_NAME AS `index`
                   FROM information_schema.STATISTICS st
                   LEFT JOIN information_schema.INDEX_STATISTICS s
                          ON s.TABLE_SCHEMA = st.TABLE_SCHEMA AND s.TABLE_NAME = st.TABLE_NAME AND s.INDEX_NAME = st.INDEX_NAME
                  WHERE st.TABLE_SCHEMA = DATABASE() AND st.INDEX_NAME <> 'PRIMARY' AND s.INDEX_NAME IS NULL"
            );
        } else {
            $out['source'] = 'information_schema (limitato)';
            $out['warning'] ??= 'performance_schema e userstat sono disattivi: non e\' possibile sapere quali tabelle/indici vengono letti. '
                            . 'Attivare performance_schema=ON in my.cnf (MySQL/MariaDB) oppure userstat=1 (MariaDB) e riavviare.';
            $out['tables_without_recorded_writes'] = $this->tryAll(
                "SELECT TABLE_NAME AS `table`, TABLE_ROWS AS rows_estimate, CREATE_TIME AS created
                   FROM information_schema.TABLES
                  WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' AND UPDATE_TIME IS NULL"
            );
        }

        // tabelle vuote: la stima di information_schema non e' affidabile, si verifica con una lettura reale
        $empty = [];
        foreach ($this->all("SELECT TABLE_NAME AS t FROM information_schema.TABLES
                              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' AND TABLE_ROWS < 50") as $r) {
            $has = $this->tryAll('SELECT 1 FROM ' . TargetDb::ident($r['t']) . ' LIMIT 1');
            if ($has === []) {
                $empty[] = $r['t'];
            }
        }
        $out['empty_tables'] = $empty;
        return $out;
    }

    /**
     * Campi mai valorizzati: per ogni colonna conta i valori non NULL / non vuoti
     * e verifica se contiene sempre lo stesso valore. Una sola scansione per tabella.
     */
    public function columnUsage(?string $table, int $maxTableRows): array
    {
        $params = [];
        $where = '';
        if ($table !== null && $table !== '') {
            $where = ' AND c.TABLE_NAME = ?';
            $params[] = $table;
        }
        $cols = $this->all(
            "SELECT c.TABLE_NAME AS t, c.COLUMN_NAME AS c, c.DATA_TYPE AS dt, c.IS_NULLABLE AS n, c.COLUMN_DEFAULT AS d,
                    c.COLUMN_KEY AS k, tb.TABLE_ROWS AS est
               FROM information_schema.COLUMNS c
               JOIN information_schema.TABLES tb ON tb.TABLE_SCHEMA = c.TABLE_SCHEMA AND tb.TABLE_NAME = c.TABLE_NAME
              WHERE c.TABLE_SCHEMA = DATABASE() AND tb.TABLE_TYPE = 'BASE TABLE' $where
              ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION",
            $params
        );
        if (!$cols) {
            throw new RuntimeException($table ? "Tabella '$table' non trovata" : 'Nessuna tabella nel database');
        }
        $byTable = [];
        foreach ($cols as $c) {
            $byTable[$c['t']][] = $c;
        }

        $textTypes = ['char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext', 'enum', 'set'];
        $noMinMax  = ['blob', 'tinyblob', 'mediumblob', 'longblob', 'json', 'geometry', 'point', 'linestring', 'polygon',
                      'multipoint', 'multilinestring', 'multipolygon', 'geometrycollection', 'longtext', 'mediumtext', 'text'];
        $out = ['tables' => [], 'skipped' => []];

        foreach ($byTable as $t => $tcols) {
            $est = (int)$tcols[0]['est'];
            if ($table === null && $est > $maxTableRows) {
                $out['skipped'][] = ['table' => $t, 'rows_estimate' => $est,
                    'reason' => "oltre $maxTableRows righe: richiamare column_usage indicando la tabella"];
                continue;
            }
            $sel = ['COUNT(*) AS `__n`'];
            foreach ($tcols as $i => $c) {
                $id = TargetDb::ident($c['c']);
                $sel[] = "COUNT($id) AS `nn$i`";
                if (in_array($c['dt'], $textTypes, true)) {
                    $sel[] = "SUM($id <> '') AS `ne$i`";
                }
                if (!in_array($c['dt'], $noMinMax, true)) {
                    $sel[] = "(MIN($id) <=> MAX($id)) AS `same$i`, MIN($id) AS `min$i`";
                }
            }
            $r = $this->tryAll('SELECT ' . implode(', ', $sel) . ' FROM ' . TargetDb::ident($t));
            if ($r === null) {
                $out['skipped'][] = ['table' => $t, 'reason' => 'query non eseguibile (privilegi o timeout)'];
                continue;
            }
            $r = $r[0];
            $n = (int)$r['__n'];
            if ($n === 0) {
                $out['tables'][] = ['table' => $t, 'rows' => 0, 'note' => 'tabella vuota'];
                continue;
            }
            $find = [];
            foreach ($tcols as $i => $c) {
                $nn = (int)$r["nn$i"];
                $ne = isset($r["ne$i"]) ? (int)$r["ne$i"] : null;
                $status = null;
                if ($nn === 0) {
                    $status = 'sempre NULL';
                } elseif ($ne === 0) {
                    $status = 'sempre vuoto';
                } elseif ($c['k'] === '' && $n > 1 && !empty($r["same$i"]) && $nn === $n) {
                    $val = (string)$r["min$i"];
                    $status = 'valore costante: ' . mb_substr($val, 0, 60)
                            . ((string)$c['d'] !== '' && trim((string)$c['d'], "'") === $val ? ' (uguale al default)' : '');
                }
                if ($status !== null) {
                    $find[] = ['column' => $c['c'], 'type' => $c['dt'], 'status' => $status,
                               'filled_pct' => round(100 * ($ne ?? $nn) / $n, 2)];
                } elseif (($ne ?? $nn) / $n < 0.01) {
                    $find[] = ['column' => $c['c'], 'type' => $c['dt'], 'status' => 'valorizzato in meno dell\'1% delle righe',
                               'filled_pct' => round(100 * ($ne ?? $nn) / $n, 3)];
                }
            }
            $out['tables'][] = ['table' => $t, 'rows' => $n, 'columns_total' => count($tcols), 'unused_columns' => $find];
        }
        $out['note'] = 'Un campo "sempre NULL/vuoto/costante" e\' candidato alla rimozione, ma va verificato che il codice applicativo non lo usi.';
        return $out;
    }

    // ------------------------------------------------------------------
    // Performance
    // ------------------------------------------------------------------

    public function performanceReport(): array
    {
        $st = TargetDb::pairs($this->pdo, 'SHOW GLOBAL STATUS');
        $va = TargetDb::pairs($this->pdo, 'SHOW GLOBAL VARIABLES');
        $n  = fn(string $k) => (float)($st[$k] ?? 0);
        $up = max(1, $n('Uptime'));
        $rec = [];

        $bpReq  = $n('Innodb_buffer_pool_read_requests');
        $bpHit  = $bpReq > 0 ? round(100 * (1 - $n('Innodb_buffer_pool_reads') / $bpReq), 3) : null;
        $tmpAll = $n('Created_tmp_tables');
        $tmpDsk = $tmpAll > 0 ? round(100 * $n('Created_tmp_disk_tables') / $tmpAll, 2) : null;
        $maxCon = (float)($va['max_connections'] ?? 0);
        $conPct = $maxCon > 0 ? round(100 * $n('Max_used_connections') / $maxCon, 1) : null;

        $innodbData = $this->tryAll("SELECT COALESCE(SUM(DATA_LENGTH + INDEX_LENGTH), 0) AS b FROM information_schema.TABLES WHERE ENGINE = 'InnoDB'");
        $innodbBytes = (float)($innodbData[0]['b'] ?? 0);
        $bpSize = (float)($va['innodb_buffer_pool_size'] ?? 0);

        $metrics = [
            'version'                       => $va['version'] ?? null,
            'uptime_days'                   => round($up / 86400, 2),
            'queries_per_second'            => round($n('Questions') / $up, 2),
            'slow_queries'                  => (int)$n('Slow_queries'),
            'slow_query_log'                => $va['slow_query_log'] ?? null,
            'long_query_time'               => $va['long_query_time'] ?? null,
            'connections_max_used_pct'      => $conPct,
            'threads_connected'             => (int)$n('Threads_connected'),
            'aborted_connects'              => (int)$n('Aborted_connects'),
            'innodb_buffer_pool_size_mb'    => round($bpSize / 1048576),
            'innodb_data_total_mb'          => round($innodbBytes / 1048576),
            'innodb_buffer_pool_hit_pct'    => $bpHit,
            'tmp_tables_on_disk_pct'        => $tmpDsk,
            'select_full_join'              => (int)$n('Select_full_join'),
            'select_scan'                   => (int)$n('Select_scan'),
            'sort_merge_passes'             => (int)$n('Sort_merge_passes'),
            'table_open_cache'              => $va['table_open_cache'] ?? null,
            'opened_tables'                 => (int)$n('Opened_tables'),
            'innodb_row_lock_waits'         => (int)$n('Innodb_row_lock_waits'),
            'innodb_row_lock_time_avg_ms'   => (int)$n('Innodb_row_lock_time_avg'),
        ];

        if ($bpHit !== null && $bpHit < 99 && $up > 3600) {
            $rec[] = "Buffer pool hit ratio $bpHit%: aumentare innodb_buffer_pool_size (ora {$metrics['innodb_buffer_pool_size_mb']} MB).";
        }
        if ($bpSize > 0 && $innodbBytes > $bpSize * 1.5) {
            $rec[] = "I dati InnoDB ({$metrics['innodb_data_total_mb']} MB) superano di molto il buffer pool ({$metrics['innodb_buffer_pool_size_mb']} MB): valutare di portarlo al 50-70% della RAM su un server dedicato.";
        }
        if ($tmpDsk !== null && $tmpDsk > 25) {
            $rec[] = "Il $tmpDsk% delle tabelle temporanee finisce su disco: rivedere GROUP BY/ORDER BY su colonne TEXT/BLOB e tmp_table_size/max_heap_table_size.";
        }
        if ($conPct !== null && $conPct > 85) {
            $rec[] = "Picco di connessioni al $conPct% di max_connections: rischio di 'Too many connections'.";
        }
        if ($up > 3600 && $n('Select_full_join') / $up * 3600 > 10) {
            $rec[] = 'Molte JOIN senza indice (Select_full_join): controllare le query in top_statements con no_index_used > 0.';
        }
        if (strtoupper((string)($va['slow_query_log'] ?? 'OFF')) === 'OFF') {
            $rec[] = 'slow_query_log disattivo: attivarlo (long_query_time = 1 o 2) per individuare le query lente.';
        }
        if ($n('Opened_tables') / $up > 5) {
            $rec[] = 'Opened_tables cresce rapidamente: aumentare table_open_cache.';
        }

        $out = ['metrics' => $metrics];

        $psReadable = $this->perfSchemaOn()
            && $this->tryAll('SELECT 1 FROM performance_schema.events_statements_summary_by_digest LIMIT 1') !== null;
        if ($psReadable) {
            $out['top_statements_by_total_time'] = $this->tryAll(
                "SELECT LEFT(DIGEST_TEXT, 400) AS statement, COUNT_STAR AS executions,
                        ROUND(SUM_TIMER_WAIT / 1e12, 2) AS total_s, ROUND(AVG_TIMER_WAIT / 1e9, 2) AS avg_ms,
                        ROUND(MAX_TIMER_WAIT / 1e9, 2) AS max_ms,
                        ROUND(SUM_ROWS_EXAMINED / COUNT_STAR) AS rows_examined_avg, ROUND(SUM_ROWS_SENT / COUNT_STAR) AS rows_sent_avg,
                        SUM_NO_INDEX_USED AS no_index_used, SUM_CREATED_TMP_DISK_TABLES AS tmp_disk_tables, LAST_SEEN AS last_seen
                   FROM performance_schema.events_statements_summary_by_digest
                  WHERE SCHEMA_NAME = DATABASE() AND DIGEST_TEXT IS NOT NULL
                  ORDER BY SUM_TIMER_WAIT DESC LIMIT 15"
            );
            $out['full_scan_statements'] = $this->tryAll(
                "SELECT LEFT(DIGEST_TEXT, 400) AS statement, COUNT_STAR AS executions, SUM_NO_INDEX_USED AS no_index_used,
                        ROUND(SUM_ROWS_EXAMINED / COUNT_STAR) AS rows_examined_avg
                   FROM performance_schema.events_statements_summary_by_digest
                  WHERE SCHEMA_NAME = DATABASE() AND SUM_NO_INDEX_USED > 0 AND DIGEST_TEXT NOT LIKE 'SHOW%'
                  ORDER BY SUM_ROWS_EXAMINED DESC LIMIT 10"
            );
        } else {
            $out['top_statements_by_total_time'] = null;
            $rec[] = $this->perfSchemaOn()
                ? 'performance_schema non leggibile dall\'utente della connessione: GRANT SELECT ON performance_schema.* TO <utente> per le statistiche per query.'
                : 'performance_schema disattivo: le statistiche per query non sono disponibili (attivare performance_schema=ON e riavviare).';
        }

        $out['tables_without_primary_key'] = array_column($this->all(
            "SELECT t.TABLE_NAME AS t FROM information_schema.TABLES t
               LEFT JOIN information_schema.TABLE_CONSTRAINTS c
                      ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME AND c.CONSTRAINT_TYPE = 'PRIMARY KEY'
              WHERE t.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = 'BASE TABLE' AND c.CONSTRAINT_NAME IS NULL"
        ), 't');
        if ($out['tables_without_primary_key']) {
            $rec[] = 'Tabelle senza PRIMARY KEY: penalizzano InnoDB e la replica. Aggiungere una chiave primaria.';
        }

        $out['non_innodb_tables'] = $this->all(
            "SELECT TABLE_NAME AS `table`, ENGINE AS engine FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' AND ENGINE <> 'InnoDB'"
        );
        if ($out['non_innodb_tables']) {
            $rec[] = 'Tabelle non InnoDB (es. MyISAM): lock a livello di tabella e nessuna transazione; inoltre il backup con --single-transaction non e\' consistente su queste tabelle.';
        }

        $out['fragmented_tables'] = $this->all(
            "SELECT TABLE_NAME AS `table`, ROUND(DATA_LENGTH / 1048576, 1) AS data_mb, ROUND(DATA_FREE / 1048576, 1) AS free_mb
               FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND DATA_FREE > 50 * 1048576 AND DATA_FREE > DATA_LENGTH * 0.2
              ORDER BY DATA_FREE DESC"
        );
        if ($out['fragmented_tables']) {
            $rec[] = 'Tabelle frammentate: valutare OPTIMIZE TABLE in una finestra di manutenzione.';
        }

        $out['redundant_indexes'] = $this->redundantIndexes();
        if ($out['redundant_indexes']) {
            $rec[] = 'Indici ridondanti (prefisso di un altro indice): rallentano le scritture e occupano spazio.';
        }

        $out['largest_tables'] = array_slice($this->listTables(), 0, 10);
        $out['recommendations'] = $rec;
        return $out;
    }

    /** Un indice e' ridondante se le sue colonne sono il prefisso di un altro indice della stessa tabella. */
    private function redundantIndexes(): array
    {
        $rows = $this->all(
            "SELECT TABLE_NAME AS t, INDEX_NAME AS i, NON_UNIQUE AS nu, INDEX_TYPE AS ty,
                    GROUP_CONCAT(CONCAT(COLUMN_NAME, IFNULL(CONCAT('(', SUB_PART, ')'), '')) ORDER BY SEQ_IN_INDEX) AS cols
               FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE()
              GROUP BY TABLE_NAME, INDEX_NAME, NON_UNIQUE, INDEX_TYPE"
        );
        $by = [];
        foreach ($rows as $r) {
            if ($r['ty'] === 'BTREE') {
                $by[$r['t']][] = $r;
            }
        }
        $out = [];
        foreach ($by as $t => $idx) {
            foreach ($idx as $a) {
                if ($a['i'] === 'PRIMARY' || !(int)$a['nu']) {
                    continue; // PRIMARY e UNIQUE impongono un vincolo: non sono mai "ridondanti"
                }
                foreach ($idx as $b) {
                    if ($a['i'] === $b['i']) {
                        continue;
                    }
                    $dup = $a['cols'] === $b['cols'];
                    if (($dup && ($b['i'] === 'PRIMARY' || !(int)$b['nu'] || strcmp($a['i'], $b['i']) > 0))
                        || (!$dup && str_starts_with($b['cols'] . ',', $a['cols'] . ','))) {
                        $out[] = ['table' => $t, 'redundant_index' => $a['i'], 'columns' => $a['cols'],
                                  'covered_by' => $b['i'], 'covered_by_columns' => $b['cols']];
                        break;
                    }
                }
            }
        }
        return $out;
    }

    public function explain(string $sql): array
    {
        $sk = TargetDb::skeleton($sql);
        if (!preg_match('/^\(*\s*(SELECT|WITH)\b/i', $sk) || TargetDb::readonlyViolation($sql)) {
            throw new RuntimeException('explain_query accetta solo una singola SELECT');
        }
        return $this->all('EXPLAIN ' . $sql);
    }

    public function processList(): array
    {
        return $this->all(
            "SELECT ID AS id, USER AS user, HOST AS host, DB AS db, COMMAND AS command, TIME AS time_s, STATE AS state, LEFT(INFO, 500) AS query
               FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Sleep' OR TIME < 60 ORDER BY TIME DESC LIMIT 100"
        );
    }

    // ------------------------------------------------------------------
    // Sicurezza
    // ------------------------------------------------------------------

    public function securityAudit(): array
    {
        $f  = [];
        $add = function (string $sev, string $title, string $detail, string $fix) use (&$f) {
            $f[] = ['severity' => $sev, 'title' => $title, 'detail' => $detail, 'recommendation' => $fix];
        };
        $va = TargetDb::pairs($this->pdo, 'SHOW GLOBAL VARIABLES');
        $v  = fn(string $k) => strtoupper((string)($va[$k] ?? ''));
        $notes = [];

        // --- account ---
        $users = $this->tryAll('SELECT * FROM mysql.user');
        if ($users === null) {
            $notes[] = 'L\'utente della connessione non puo\' leggere mysql.user: analisi degli account saltata '
                     . '(per includerla: GRANT SELECT ON mysql.user TO ... oppure usare una connessione amministrativa in sola lettura).';
        } else {
            $socketPlugins = ['unix_socket', 'auth_socket', 'auth_pam', 'mysql_no_login'];
            $privCols = ['Super_priv', 'File_priv', 'Grant_priv', 'Shutdown_priv', 'Process_priv', 'Create_user_priv'];
            foreach ($users as $u) {
                $u = array_change_key_case($u, CASE_LOWER);
                $name = (string)($u['user'] ?? '');
                $host = (string)($u['host'] ?? '');
                $acct = "'$name'@'$host'";
                $plugin = (string)($u['plugin'] ?? '');
                $local = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
                $locked = ($u['account_locked'] ?? 'N') === 'Y';
                $system = in_array($name, ['mysql.sys', 'mysql.session', 'mysql.infoschema', 'mariadb.sys'], true)
                    || ($name === 'mysql' && $local); // account di servizio MariaDB via unix_socket
                if ($system || $locked) {
                    continue;
                }
                if ($name === '') {
                    $add('alta', "Utente anonimo $acct", 'Chiunque raggiunga il server puo\' collegarsi senza nome utente.', "DROP USER ''@'$host';");
                }
                $noPass = ($u['authentication_string'] ?? '') === '' && ($u['password'] ?? '') === '';
                if ($noPass && !in_array($plugin, $socketPlugins, true)) {
                    $add($local ? 'alta' : 'critica', "Account senza password: $acct", "Plugin: " . ($plugin ?: 'n/d'), "ALTER USER $acct IDENTIFIED BY '<password robusta>';");
                }
                if ($name === 'root' && !$local) {
                    $add('critica', "root accessibile da remoto: $acct", 'L\'account root dovrebbe collegarsi solo da localhost.', "DROP USER $acct; (usare account nominali con privilegi minimi)");
                } elseif ($host === '%' && $name !== '') {
                    $add('media', "Account valido da qualsiasi host: $acct", 'Host \'%\' espone l\'account a tentativi di accesso da tutta la rete.', 'Limitare l\'host all\'IP dell\'applicazione o a localhost.');
                }
                $has = array_values(array_filter($privCols, fn($c) => ($u[strtolower($c)] ?? 'N') === 'Y'));
                if ($has && $name !== 'root' && $name !== '') {
                    $add(in_array('Super_priv', $has, true) || in_array('File_priv', $has, true) || in_array('Grant_priv', $has, true) ? 'alta' : 'bassa',
                        "Privilegi amministrativi globali: $acct", implode(', ', $has),
                        'Revocare i privilegi globali non necessari (REVOKE ... ON *.*) e concedere solo quelli sul singolo database.');
                }
                if (in_array($plugin, ['mysql_old_password'], true)) {
                    $add('alta', "Plugin di autenticazione obsoleto: $acct", $plugin, 'Passare a caching_sha2_password (MySQL 8) o ed25519/mysql_native_password (MariaDB).');
                }
                if (($u['password_expired'] ?? 'N') === 'Y') {
                    $add('bassa', "Password scaduta: $acct", 'L\'account non puo\' operare finche\' la password non viene cambiata.', 'Aggiornare la password o rimuovere l\'account se inutilizzato.');
                }
            }
        }

        // --- configurazione server ---
        if ($v('local_infile') === 'ON') {
            $add('media', 'local_infile attivo', 'Permette LOAD DATA LOCAL INFILE (lettura di file dal client).', 'Impostare local_infile=0 in my.cnf se non serve.');
        }
        if (array_key_exists('secure_file_priv', $va) && (string)$va['secure_file_priv'] === '') {
            $add('media', 'secure_file_priv vuoto', 'Gli utenti con privilegio FILE possono leggere/scrivere in qualsiasi directory del server.', 'Impostare secure_file_priv su una directory dedicata (o NULL).');
        }
        $bind = (string)($va['bind_address'] ?? '');
        if (in_array($bind, ['*', '0.0.0.0', '::', ''], true)) {
            $add('media', 'MySQL in ascolto su tutte le interfacce', 'bind_address = ' . ($bind === '' ? '(non impostato)' : $bind),
                'Se il DB e\' usato solo in locale impostare bind-address=127.0.0.1; altrimenti filtrare la porta 3306 con firewall per IP.');
        }
        $ssl = $v('have_ssl') ?: $v('have_openssl');
        if ($ssl !== '' && $ssl !== 'YES') {
            $add('media', 'TLS non disponibile sul server', "have_ssl = $ssl", 'Configurare ssl_cert/ssl_key per cifrare le connessioni remote.');
        }
        if (array_key_exists('require_secure_transport', $va) && $v('require_secure_transport') === 'OFF' && !in_array($bind, ['127.0.0.1', 'localhost', '::1'], true)) {
            $add('bassa', 'Connessioni in chiaro ammesse', 'require_secure_transport = OFF', 'Attivare require_secure_transport=ON oppure REQUIRE SSL sugli account remoti.');
        }
        $hasPolicy = (bool)array_filter(array_keys($va), fn($k) => str_starts_with($k, 'validate_password') || str_starts_with($k, 'simple_password_check') || str_starts_with($k, 'cracklib_password_check'));
        if (!$hasPolicy) {
            $add('bassa', 'Nessuna policy sulle password', 'Non risultano attivi validate_password / simple_password_check.', 'Installare il plugin/componente di validazione password.');
        }
        if ($v('general_log') === 'ON') {
            $add('bassa', 'general_log attivo', 'Registra tutte le query (anche con dati sensibili) e degrada le prestazioni.', 'Disattivarlo fuori dalle sessioni di debug.');
        }
        $mode = $v('sql_mode');
        if (!str_contains($mode, 'STRICT_TRANS_TABLES') && !str_contains($mode, 'STRICT_ALL_TABLES') && !str_contains($mode, 'TRADITIONAL')) {
            $add('bassa', 'sql_mode non strict', 'I dati non validi vengono troncati in silenzio invece di generare errore.', 'Aggiungere STRICT_TRANS_TABLES a sql_mode.');
        }
        if ($v('log_bin') === 'OFF') {
            $add('info', 'Binary log disattivo', 'Senza binlog non e\' possibile il ripristino point-in-time tra un backup e l\'altro.', 'Valutare log_bin=ON con expire_logs_days adeguato.');
        }
        if ($v('skip_name_resolve') === 'OFF') {
            $add('info', 'skip_name_resolve disattivo', 'L\'autenticazione dipende dal DNS inverso (lentezza e possibile spoofing).', 'Impostare skip_name_resolve=ON e usare IP negli host degli account.');
        }

        // --- varie ---
        $test = $this->tryAll("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'test'");
        if ($test) {
            $add('bassa', 'Database "test" presente', 'Database di esempio spesso accessibile a tutti gli utenti.', 'DROP DATABASE test;');
        }
        $cipher = TargetDb::pairs($this->pdo, "SHOW SESSION STATUS LIKE 'Ssl_cipher'")['Ssl_cipher'] ?? '';
        $grants = $this->tryAll('SHOW GRANTS');
        $grantList = $grants ? array_map(fn($g) => preg_replace("/IDENTIFIED BY PASSWORD '[^']*'/", "IDENTIFIED BY PASSWORD '***'", (string)array_values($g)[0]), $grants) : [];
        foreach ($grantList as $g) {
            if (preg_match('/GRANT ALL PRIVILEGES ON \*\.\*/i', $g)) {
                $add('media', 'La connessione registrata usa un account con ALL PRIVILEGES globali', $g,
                    'Per l\'uso via MCP registrare un account dedicato con i soli privilegi necessari (SELECT per analisi; DML/DDL solo se serve execute_sql).');
            }
        }

        $order = ['critica' => 0, 'alta' => 1, 'media' => 2, 'bassa' => 3, 'info' => 4];
        usort($f, fn($a, $b) => $order[$a['severity']] <=> $order[$b['severity']]);
        $sum = array_count_values(array_column($f, 'severity'));

        return [
            'server_version'            => $va['version'] ?? null,
            'summary'                   => $sum,
            'findings'                  => $f,
            'this_connection_encrypted' => $cipher !== '',
            'this_connection_grants'    => $grantList,
            'notes'                     => $notes,
        ];
    }
}

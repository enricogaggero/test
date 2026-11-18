<?php
declare(strict_types=1);

/**
 * Server MCP (trasporto Streamable HTTP, risposte JSON).
 * Ogni sessione MCP nasce bloccata: i tool funzionano solo dopo la validazione
 * user/password (tool `login`, oppure header Authorization: Basic alla initialize).
 */
final class McpServer
{
    private const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];

    private ?string $tokenHash = null;
    private ?array $user = null;       // utente autenticato nella sessione corrente
    private ?string $newToken = null;  // valorizzato quando la richiesta e' una initialize

    public function handleHttp(): void
    {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');

        if ($why = request_denied_reason()) {
            $this->httpError(403, $why);
        }
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        if ($method === 'DELETE') {
            if ($t = $this->headerToken()) {
                q('DELETE FROM dba_mcp_sessions WHERE token_hash = ?', [hash('sha256', $t)]);
            }
            http_response_code(204);
            return;
        }
        if ($method !== 'POST') {
            header('Allow: POST, DELETE');
            $this->httpError(405, 'Usare POST (lo stream SSE via GET non e\' supportato)');
        }

        $msg = json_decode((string)file_get_contents('php://input'), true);
        if (!is_array($msg)) {
            $this->out(['jsonrpc' => '2.0', 'id' => null, 'error' => ['code' => -32700, 'message' => 'JSON non valido']], 400);
        }
        $batch = array_is_list($msg);
        $responses = [];
        foreach ($batch ? $msg : [$msg] as $m) {
            $r = is_array($m) ? $this->dispatch($m) : null;
            if ($r !== null) {
                $responses[] = $r;
            }
        }
        if ($this->newToken) {
            header('Mcp-Session-Id: ' . $this->newToken);
        }
        if (!$responses) {
            http_response_code(202);
            return;
        }
        $this->out($batch ? $responses : $responses[0]);
    }

    private function dispatch(array $m): ?array
    {
        $id = $m['id'] ?? null;
        $method = (string)($m['method'] ?? '');
        $isNotification = !array_key_exists('id', $m);
        $params = is_array($m['params'] ?? null) ? $m['params'] : [];

        try {
            if ($method === 'initialize') {
                return $this->ok($id, $this->initialize($params));
            }
            $this->loadSession();
            if ($isNotification) {
                return null;
            }
            return match ($method) {
                'ping'       => $this->ok($id, new stdClass()),
                'tools/list' => $this->ok($id, ['tools' => self::tools()]),
                'tools/call' => $this->ok($id, $this->callTool((string)($params['name'] ?? ''), (array)($params['arguments'] ?? []))),
                'resources/list' => $this->ok($id, ['resources' => []]),
                'prompts/list'   => $this->ok($id, ['prompts' => []]),
                default      => ['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => -32601, 'message' => "Metodo non supportato: $method"]],
            };
        } catch (McpHttpException $e) {
            $this->httpError($e->getCode(), $e->getMessage(), $id);
        } catch (Throwable $e) {
            error_log('[dbadmin-mcp] ' . $e->getMessage());
            return $isNotification ? null
                : ['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => -32603, 'message' => 'Errore interno del server']];
        }
    }

    // ---------------- sessione ----------------

    private function initialize(array $params): array
    {
        $userId = null;
        [$bu, $bp] = $this->basicCredentials();
        if ($bu !== null) {
            try {
                $this->user = login_check($bu, (string)$bp, 'can_mcp', 'mcp');
                $userId = (int)$this->user['id'];
            } catch (PDOException $e) {
                throw $e;
            } catch (RuntimeException $e) {
                header('WWW-Authenticate: Basic realm="dbadmin-mcp"');
                throw new McpHttpException($e->getMessage(), 401);
            }
        }
        $mc = cfg()['mcp'] ?? [];
        q('DELETE FROM dba_mcp_sessions WHERE last_seen_at < NOW() - INTERVAL ? MINUTE OR created_at < NOW() - INTERVAL ? HOUR',
            [(int)($mc['idle_minutes'] ?? 30), (int)($mc['max_hours'] ?? 8)]);

        $this->newToken = bin2hex(random_bytes(32));
        $this->tokenHash = hash('sha256', $this->newToken);
        $ci = $params['clientInfo'] ?? [];
        q('INSERT INTO dba_mcp_sessions (token_hash, user_id, ip, client_info) VALUES (?,?,?,?)', [
            $this->tokenHash, $userId, client_ip(),
            mb_substr(trim(($ci['name'] ?? '') . ' ' . ($ci['version'] ?? '')), 0, 255) ?: null,
        ]);

        $pv = (string)($params['protocolVersion'] ?? '');
        return [
            'protocolVersion' => in_array($pv, self::PROTOCOLS, true) ? $pv : self::PROTOCOLS[0],
            'capabilities'    => ['tools' => new stdClass()],
            'serverInfo'      => ['name' => 'dbadmin-mcp', 'title' => APP_NAME, 'version' => APP_VERSION],
            'instructions'    => $userId
                ? 'Sessione autenticata. Usa list_connections per vedere i database registrati.'
                : 'Sessione BLOCCATA: prima di qualsiasi altro tool chiedi all\'utente username e password e chiama il tool `login`. '
                  . 'La sessione scade per inattivita\' e va riautenticata. Poi usa list_connections per vedere i database registrati.',
        ];
    }

    private function loadSession(): void
    {
        if ($this->tokenHash) {
            return; // initialize nello stesso batch
        }
        $t = $this->headerToken();
        if (!$t) {
            throw new McpHttpException('Header Mcp-Session-Id mancante: eseguire initialize', 400);
        }
        $mc = cfg()['mcp'] ?? [];
        $hash = hash('sha256', $t);
        $s = q('SELECT s.*, (s.last_seen_at < NOW() - INTERVAL ? MINUTE OR s.created_at < NOW() - INTERVAL ? HOUR) AS expired
                  FROM dba_mcp_sessions s WHERE s.token_hash = ?',
            [(int)($mc['idle_minutes'] ?? 30), (int)($mc['max_hours'] ?? 8), $hash])->fetch();
        if (!$s || $s['expired']) {
            q('DELETE FROM dba_mcp_sessions WHERE token_hash = ?', [$hash]);
            throw new McpHttpException('Sessione MCP scaduta o inesistente: reinizializzare e rifare il login', 404);
        }
        $this->tokenHash = $hash;
        q('UPDATE dba_mcp_sessions SET last_seen_at = NOW() WHERE token_hash = ?', [$hash]);
        if ($s['user_id']) {
            $u = q('SELECT * FROM dba_users WHERE id = ? AND active = 1 AND can_mcp = 1', [$s['user_id']])->fetch();
            $this->user = $u ?: null; // utente disattivato dalla GUI => sessione di nuovo bloccata
        }
    }

    private function headerToken(): ?string
    {
        $t = $_SERVER['HTTP_MCP_SESSION_ID'] ?? '';
        return preg_match('/^[a-f0-9]{64}$/', $t) ? $t : null;
    }

    private function basicCredentials(): array
    {
        if (isset($_SERVER['PHP_AUTH_USER'])) {
            return [$_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ?? ''];
        }
        $h = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
        if (stripos($h, 'basic ') === 0 && ($d = base64_decode(substr($h, 6), true)) !== false && str_contains($d, ':')) {
            return explode(':', $d, 2);
        }
        return [null, null];
    }

    // ---------------- tool ----------------

    private function callTool(string $name, array $a): array
    {
        try {
            if ($name === 'login') {
                $data = $this->toolLogin($a);
            } elseif (!$this->user) {
                throw new RuntimeException('Sessione non autenticata: chiedi username e password all\'utente e chiama prima il tool `login`.');
            } else {
                $data = $this->runTool($name, $a);
            }
            return ['content' => [['type' => 'text', 'text' => self::json($data)]], 'isError' => false];
        } catch (PDOException $e) {
            return $this->toolError('Errore MySQL: ' . $e->getMessage());
        } catch (RuntimeException $e) {
            return $this->toolError($e->getMessage());
        }
    }

    private function toolError(string $msg): array
    {
        return ['content' => [['type' => 'text', 'text' => $msg]], 'isError' => true];
    }

    private function toolLogin(array $a): array
    {
        $u = login_check((string)($a['username'] ?? ''), (string)($a['password'] ?? ''), 'can_mcp', 'mcp');
        q('UPDATE dba_mcp_sessions SET user_id = ? WHERE token_hash = ?', [$u['id'], $this->tokenHash]);
        $this->user = $u;
        $mc = cfg()['mcp'] ?? [];
        return [
            'authenticated' => true,
            'user'          => $u['username'],
            'can_write'     => (bool)$u['can_write'],
            'session'       => 'scade dopo ' . (int)($mc['idle_minutes'] ?? 30) . ' minuti di inattivita\' (max ' . (int)($mc['max_hours'] ?? 8) . ' ore)',
            'connections'   => array_column(conn_all(), 'name'),
        ];
    }

    private function runTool(string $name, array $a): mixed
    {
        $un = $this->user['username'];
        $mc = cfg()['mcp'] ?? [];
        $timeout = (int)($mc['query_timeout'] ?? 30);

        if ($name === 'logout') {
            q('DELETE FROM dba_mcp_sessions WHERE token_hash = ?', [$this->tokenHash]);
            audit('mcp', $un, 'logout');
            return ['authenticated' => false];
        }
        if ($name === 'list_connections') {
            return array_map(fn($c) => [
                'name' => $c['name'], 'host' => $c['host'], 'port' => (int)$c['port'], 'database' => $c['db_name'],
                'write_enabled' => (bool)$c['allow_write'], 'backup_enabled' => (bool)$c['backup_enabled'], 'notes' => $c['notes'],
            ], conn_all());
        }
        if ($name === 'backup_status') {
            $cid = !empty($a['connection']) ? (int)conn_get((string)$a['connection'])['id'] : null;
            return array_map(fn($b) => [
                'connection' => $b['conn_name'], 'started_at' => $b['started_at'], 'finished_at' => $b['finished_at'],
                'status' => $b['status'], 'size' => human_bytes($b['size_bytes'] === null ? null : (int)$b['size_bytes']),
                's3_key' => $b['s3_key'], 'trigger' => $b['trigger_by'], 'message' => $b['message'],
            ], Backup::history($cid, (int)($a['limit'] ?? 20)));
        }

        // da qui in poi tutti i tool lavorano su una connessione registrata
        $known = array_column(self::tools(), 'name');
        if (!in_array($name, $known, true)) {
            throw new RuntimeException("Tool sconosciuto: $name");
        }
        $conn = conn_get((string)($a['connection'] ?? ''));

        if ($name === 'backup_now') {
            new S3(s3_config()); // fallisce subito se S3 non e' configurato
            Backup::spawn((int)$conn['id'], 'mcp');
            audit('mcp', $un, 'backup_now', $conn['name']);
            return ['started' => true, 'note' => 'Backup avviato in background: controllare l\'esito con backup_status.'];
        }

        $pdo = TargetDb::connect($conn);
        $an = new Analyzer($pdo);

        switch ($name) {
            case 'server_info':
                return $an->serverInfo();
            case 'list_tables':
                return $an->listTables();
            case 'describe_table':
                return $an->describeTable((string)($a['table'] ?? ''));
            case 'process_list':
                return $an->processList();
            case 'run_query':
                $sql = (string)($a['sql'] ?? '');
                $max = max(1, min(5000, (int)($a['max_rows'] ?? ($mc['max_rows'] ?? 200))));
                audit('mcp', $un, 'run_query', $conn['name'], $sql);
                return TargetDb::readQuery($pdo, $sql, $max, $timeout);
            case 'explain_query':
                TargetDb::setTimeout($pdo, $timeout);
                return $an->explain((string)($a['sql'] ?? ''));
            case 'execute_sql':
                return $this->toolExecute($pdo, $conn, $a);
            case 'unused_objects':
                audit('mcp', $un, $name, $conn['name']);
                return $an->unusedObjects();
            case 'column_usage':
                audit('mcp', $un, $name, $conn['name'], (string)($a['table'] ?? ''));
                TargetDb::setTimeout($pdo, max($timeout, 120));
                return $an->columnUsage(isset($a['table']) ? (string)$a['table'] : null, (int)($a['max_table_rows'] ?? 2000000));
            case 'performance_report':
                audit('mcp', $un, $name, $conn['name']);
                return $an->performanceReport();
            case 'security_audit':
                audit('mcp', $un, $name, $conn['name']);
                return $an->securityAudit();
        }
        throw new RuntimeException("Tool sconosciuto: $name");
    }

    /** Aggiornamenti (DML/DDL): serve utente con can_write, connessione con allow_write e conferma esplicita. */
    private function toolExecute(PDO $pdo, array $conn, array $a): array
    {
        $un = $this->user['username'];
        $sql = trim((string)($a['sql'] ?? ''));
        if (!$this->user['can_write']) {
            throw new RuntimeException('L\'utente non e\' abilitato alla scrittura (flag "Scrittura via MCP" in GUI → Utenti).');
        }
        if (!$conn['allow_write']) {
            throw new RuntimeException("La connessione '{$conn['name']}' e' in sola lettura (flag \"Consenti scrittura\" in GUI → Connessioni).");
        }
        $sk = TargetDb::skeleton($sql);
        if ($sk === '' || str_contains($sk, ';')) {
            throw new RuntimeException('E\' ammessa una sola istruzione per chiamata');
        }
        if (preg_match('/^(GRANT|REVOKE|CREATE\s+USER|DROP\s+USER|ALTER\s+USER|RENAME\s+USER|SET\s+PASSWORD|SHUTDOWN|INSTALL|UNINSTALL|DROP\s+(DATABASE|SCHEMA))\b/i', $sk)
            || preg_match('/\bINTO\s+(OUTFILE|DUMPFILE)\b|\bLOAD\s+DATA\b|\bLOAD_FILE\b/i', $sk)) {
            audit('mcp', $un, 'execute_denied', $conn['name'], $sql);
            throw new RuntimeException('Istruzione non ammessa via MCP (gestione utenti/privilegi, DROP DATABASE, accesso a file).');
        }
        $unbounded = preg_match('/^(UPDATE|DELETE)\b/i', $sk) && !preg_match('/\bWHERE\b/i', $sk);
        if (($a['confirm'] ?? false) !== true) {
            return [
                'executed' => false,
                'warning'  => $unbounded ? 'ATTENZIONE: UPDATE/DELETE senza WHERE, agisce su tutte le righe.' : null,
                'note'     => 'Anteprima: nessuna modifica eseguita. Mostra l\'istruzione all\'utente e, dopo la sua conferma esplicita, richiama execute_sql con confirm=true.',
                'sql'      => $sql,
            ];
        }
        audit('mcp', $un, 'execute_sql', $conn['name'], $sql);
        $t0 = microtime(true);
        $affected = $pdo->exec($sql);
        return ['executed' => true, 'affected_rows' => $affected, 'elapsed_ms' => round((microtime(true) - $t0) * 1000, 1)];
    }

    public static function tools(): array
    {
        $c = ['connection' => ['type' => 'string', 'description' => 'Nome della connessione registrata (vedi list_connections)']];
        $t = fn(string $name, string $desc, array $props = [], array $req = [], bool $ro = true) => [
            'name' => $name, 'description' => $desc,
            'inputSchema' => ['type' => 'object', 'properties' => $props ?: new stdClass(), 'required' => $req],
            'annotations' => ['readOnlyHint' => $ro],
        ];
        return [
            $t('login', 'Autentica la sessione MCP con username e password. Obbligatorio prima di ogni altro tool; da ripetere a ogni nuova sessione.',
                ['username' => ['type' => 'string'], 'password' => ['type' => 'string']], ['username', 'password']),
            $t('logout', 'Chiude la sessione MCP corrente.'),
            $t('list_connections', 'Elenca i database registrati (senza credenziali).'),
            $t('server_info', 'Versione, uptime e principali variabili del server MySQL/MariaDB.', $c, ['connection']),
            $t('list_tables', 'Tabelle del database con motore, righe stimate, dimensione e spazio libero.', $c, ['connection']),
            $t('describe_table', 'Colonne, indici, chiavi esterne e CREATE TABLE di una tabella.',
                $c + ['table' => ['type' => 'string']], ['connection', 'table']),
            $t('run_query', 'Esegue UNA query in sola lettura (SELECT/SHOW/DESCRIBE/EXPLAIN/WITH) in transazione READ ONLY, con timeout e limite righe.',
                $c + ['sql' => ['type' => 'string'], 'max_rows' => ['type' => 'integer', 'description' => 'Default 200, max 5000']], ['connection', 'sql']),
            $t('explain_query', 'Piano di esecuzione (EXPLAIN) di una SELECT.', $c + ['sql' => ['type' => 'string']], ['connection', 'sql']),
            $t('execute_sql', 'Esegue UNA istruzione di aggiornamento (INSERT/UPDATE/DELETE/DDL). Richiede utente e connessione abilitati alla scrittura. '
                . 'Senza confirm=true restituisce solo l\'anteprima: chiedere sempre conferma esplicita all\'utente prima di confermare. Ogni esecuzione e\' registrata nell\'audit.',
                $c + ['sql' => ['type' => 'string'], 'confirm' => ['type' => 'boolean', 'description' => 'true per eseguire davvero']], ['connection', 'sql'], false),
            $t('unused_objects', 'Statistiche di utilizzo: tabelle mai lette/scritte e indici mai usati dall\'ultimo riavvio, tabelle vuote.', $c, ['connection']),
            $t('column_usage', 'Campi mai usati: colonne sempre NULL, sempre vuote, a valore costante o valorizzate in meno dell\'1% delle righe. '
                . 'Senza `table` analizza tutte le tabelle sotto max_table_rows (scansione completa: puo\' essere lenta).',
                $c + ['table' => ['type' => 'string', 'description' => 'Opzionale: limita a una tabella'],
                      'max_table_rows' => ['type' => 'integer', 'description' => 'Default 2000000']], ['connection']),
            $t('performance_report', 'Analisi performance: metriche server, query piu\' costose, full scan, tabelle senza PK, indici ridondanti, frammentazione, raccomandazioni.', $c, ['connection']),
            $t('process_list', 'Query in esecuzione in questo momento.', $c, ['connection']),
            $t('security_audit', 'Analisi sicurezza: account senza password/anonimi/root remoto/host %, privilegi globali, TLS, local_infile, secure_file_priv, bind_address, policy password.', $c, ['connection']),
            $t('backup_status', 'Storico dei backup su S3 (esito, dimensione, chiave S3).',
                ['connection' => ['type' => 'string', 'description' => 'Opzionale'], 'limit' => ['type' => 'integer']]),
            $t('backup_now', 'Avvia in background un backup su S3 della connessione indicata.', $c, ['connection'], false),
        ];
    }

    // ---------------- output ----------------

    private static function json(mixed $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
    }

    private function ok(mixed $id, mixed $result): array
    {
        return ['jsonrpc' => '2.0', 'id' => $id, 'result' => $result];
    }

    private function out(array $payload, int $code = 200): never
    {
        http_response_code($code);
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    private function httpError(int $code, string $msg, mixed $id = null): never
    {
        $this->out(['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => -32000, 'message' => $msg]], $code);
    }
}

final class McpHttpException extends RuntimeException
{
}

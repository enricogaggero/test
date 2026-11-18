<?php
declare(strict_types=1);

/** Accesso ai database registrati (i "target" amministrati via MCP). */
final class TargetDb
{
    public static function connect(array $conn, int $timeout = 8): PDO
    {
        $opt = [
            PDO::ATTR_ERRMODE                  => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE       => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES         => false,
            PDO::ATTR_TIMEOUT                  => $timeout,
            PDO::MYSQL_ATTR_MULTI_STATEMENTS   => false,   // una sola istruzione per chiamata
            PDO::MYSQL_ATTR_LOCAL_INFILE       => false,
        ];
        if (!empty($conn['use_ssl'])) {
            $opt[PDO::MYSQL_ATTR_SSL_CAPATH] = '/etc/ssl/certs';
            $opt[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = false;
        }
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $conn['host'], $conn['port'], $conn['db_name']);
        return new PDO($dsn, $conn['db_user'], dec($conn['db_pass_enc']), $opt);
    }

    /** Toglie commenti e letterali stringa, per analizzare la struttura dell'istruzione. */
    public static function skeleton(string $sql): string
    {
        $s = preg_replace('~/\*.*?\*/~s', ' ', $sql) ?? '';
        $s = preg_replace('~\'(?:[^\'\\\\]|\\\\.|\'\')*\'|"(?:[^"\\\\]|\\\\.|"")*"|`[^`]*`~s', "''", $s) ?? '';
        $s = preg_replace('~(--[ \t]|#)[^\n]*~', ' ', $s) ?? '';
        return trim($s, " \t\n\r;");
    }

    /** Ritorna null se l'istruzione e' ammessa in sola lettura, altrimenti il motivo del rifiuto. */
    public static function readonlyViolation(string $sql): ?string
    {
        $sk = self::skeleton($sql);
        if ($sk === '') {
            return 'Istruzione vuota';
        }
        if (str_contains($sk, ';')) {
            return 'E\' ammessa una sola istruzione per chiamata';
        }
        if (str_contains($sql, '/*!') || str_contains($sql, '/*M!')) {
            return 'Commenti eseguibili (/*! ... */) non ammessi';
        }
        if (!preg_match('/^\(*\s*(SELECT|SHOW|DESCRIBE|DESC|EXPLAIN|WITH)\b/i', $sk)) {
            return 'In sola lettura sono ammessi solo SELECT, SHOW, DESCRIBE, EXPLAIN, WITH';
        }
        if (preg_match('/\bINTO\s+(OUTFILE|DUMPFILE|@)/i', $sk) || preg_match('/\bINTO\s+\w+\s*(,|$)/i', $sk)) {
            return 'SELECT ... INTO non ammesso';
        }
        if (preg_match('/\b(FOR\s+UPDATE|LOCK\s+IN\s+SHARE\s+MODE|LOAD_FILE|SLEEP|BENCHMARK|GET_LOCK)\b/i', $sk)) {
            return 'Costrutto non ammesso in sola lettura (lock / LOAD_FILE / SLEEP / BENCHMARK)';
        }
        return null;
    }

    /** Limita la durata delle query (sintassi diversa tra MySQL e MariaDB). */
    public static function setTimeout(PDO $pdo, int $seconds): void
    {
        foreach (['SET SESSION max_statement_time = ' . $seconds, 'SET SESSION MAX_EXECUTION_TIME = ' . ($seconds * 1000)] as $sql) {
            try {
                $pdo->exec($sql);
                return;
            } catch (PDOException) {
            }
        }
    }

    /**
     * Esegue una query in sola lettura dentro una transazione READ ONLY
     * (seconda barriera lato server oltre al controllo sintattico).
     */
    public static function readQuery(PDO $pdo, string $sql, int $maxRows, int $timeout): array
    {
        if ($why = self::readonlyViolation($sql)) {
            throw new RuntimeException($why);
        }
        self::setTimeout($pdo, $timeout);
        $pdo->exec('START TRANSACTION READ ONLY');
        try {
            $st = $pdo->query($sql);
            $rows = [];
            $truncated = false;
            while ($r = $st->fetch()) {
                if (count($rows) >= $maxRows) {
                    $truncated = true;
                    break;
                }
                $rows[] = self::cleanRow($r);
            }
            $st->closeCursor();
        } finally {
            try {
                $pdo->exec('ROLLBACK');
            } catch (PDOException) {
            }
        }
        return ['row_count' => count($rows), 'truncated' => $truncated, 'rows' => $rows];
    }

    /** Rende i valori sicuri per JSON: binari in esadecimale, testi lunghi troncati. */
    public static function cleanRow(array $r): array
    {
        foreach ($r as $k => $v) {
            if (is_string($v)) {
                if (!mb_check_encoding($v, 'UTF-8')) {
                    $r[$k] = '0x' . bin2hex(substr($v, 0, 64)) . (strlen($v) > 64 ? '…' : '');
                } elseif (mb_strlen($v) > 2000) {
                    $r[$k] = mb_substr($v, 0, 2000) . '… [troncato, ' . mb_strlen($v) . ' caratteri]';
                }
            }
        }
        return $r;
    }

    public static function ident(string $name): string
    {
        if ($name === '' || str_contains($name, "\0") || strlen($name) > 64) {
            throw new RuntimeException('Identificatore non valido');
        }
        return '`' . str_replace('`', '``', $name) . '`';
    }

    public static function all(PDO $pdo, string $sql, array $params = []): array
    {
        $st = $pdo->prepare($sql);
        $st->execute($params);
        return array_map([self::class, 'cleanRow'], $st->fetchAll());
    }

    /** Come all() ma ritorna null se la query fallisce (privilegi mancanti, tabella assente...). */
    public static function tryAll(PDO $pdo, string $sql, array $params = []): ?array
    {
        try {
            return self::all($pdo, $sql, $params);
        } catch (PDOException) {
            return null;
        }
    }

    /** SHOW ... in forma chiave => valore. */
    public static function pairs(PDO $pdo, string $sql): array
    {
        $out = [];
        try {
            foreach ($pdo->query($sql)->fetchAll(PDO::FETCH_NUM) as $r) {
                $out[$r[0]] = $r[1];
            }
        } catch (PDOException) {
        }
        return $out;
    }
}

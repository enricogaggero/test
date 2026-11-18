<?php
declare(strict_types=1);

/** Dump compresso di un database registrato e caricamento su S3. */
final class Backup
{
    /** Esegue il backup completo (bloccante: usare da CLI/cron). Ritorna la riga di dba_backups. */
    public static function run(array $conn, string $trigger): array
    {
        q('INSERT INTO dba_backups (connection_id, conn_name, trigger_by, started_at) VALUES (?,?,?,NOW())',
            [$conn['id'], $conn['name'], $trigger]);
        $id = (int)appdb()->lastInsertId();
        $file = null;
        try {
            $s3cfg = s3_config();
            $s3 = new S3($s3cfg);
            $file = self::dump($conn);
            $size = (int)filesize($file);
            $key = trim($s3cfg['prefix'] . '/' . $conn['name'] . '/' . $conn['name'] . '_' . date('Ymd_His') . '.sql.gz', '/');
            $s3->putFile($key, $file);
            q("UPDATE dba_backups SET status = 'ok', finished_at = NOW(), size_bytes = ?, s3_key = ?, message = NULL WHERE id = ?",
                [$size, $key, $id]);
            audit('cron', $trigger, 'backup_ok', $conn['name'], "$key (" . human_bytes($size) . ')');
            self::applyRetention($s3, (int)$conn['id'], $s3cfg['retention']);
        } catch (Throwable $e) {
            q("UPDATE dba_backups SET status = 'error', finished_at = NOW(), message = ? WHERE id = ?",
                [mb_substr($e->getMessage(), 0, 2000), $id]);
            audit('cron', $trigger, 'backup_error', $conn['name'], $e->getMessage());
        } finally {
            if ($file && is_file($file)) {
                unlink($file);
            }
        }
        return q('SELECT * FROM dba_backups WHERE id = ?', [$id])->fetch();
    }

    /** mysqldump | gzip su file temporaneo. La password passa da un file --defaults-extra-file (mai sulla riga di comando). */
    private static function dump(array $conn): string
    {
        $b = cfg()['backup'] ?? [];
        $tmp = ($b['tmp_dir'] ?? '') ?: sys_get_temp_dir();
        if (!is_dir($tmp) || !is_writable($tmp)) {
            throw new RuntimeException("Directory temporanea non scrivibile: $tmp");
        }
        $cnf = tempnam($tmp, 'dba_cnf_');
        $out = tempnam($tmp, 'dba_dump_');
        chmod($cnf, 0600);
        chmod($out, 0600);
        $esc = fn(string $s) => '"' . addcslashes($s, "\\\"") . '"';
        file_put_contents($cnf, "[client]\nhost=" . $esc($conn['host']) . "\nport=" . (int)$conn['port']
            . "\nuser=" . $esc($conn['db_user']) . "\npassword=" . $esc(dec($conn['db_pass_enc'])) . "\n");
        try {
            $cmd = sprintf('set -o pipefail; %s --defaults-extra-file=%s %s %s | gzip -c > %s',
                escapeshellcmd($b['mysqldump_bin'] ?? 'mysqldump'), escapeshellarg($cnf),
                $b['dump_args'] ?? '--single-transaction --quick --routines --triggers --no-tablespaces',
                escapeshellarg($conn['db_name']), escapeshellarg($out));
            $proc = proc_open(['bash', '-c', $cmd], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            if (!is_resource($proc)) {
                throw new RuntimeException('Impossibile avviare mysqldump');
            }
            stream_get_contents($pipes[1]);
            $stderr = trim((string)stream_get_contents($pipes[2]));
            $code = proc_close($proc);
            if ($code !== 0) {
                throw new RuntimeException("mysqldump fallito (exit $code): " . mb_substr($stderr, 0, 1000));
            }
        } catch (Throwable $e) {
            @unlink($out);
            throw $e;
        } finally {
            @unlink($cnf);
        }
        return $out;
    }

    /** Elimina da S3 i backup riusciti piu' vecchi di N giorni (0 = conserva tutto). */
    private static function applyRetention(S3 $s3, int $connId, int $days): void
    {
        if ($days <= 0) {
            return;
        }
        $old = q("SELECT id, s3_key FROM dba_backups
                   WHERE connection_id = ? AND status = 'ok' AND s3_key IS NOT NULL AND started_at < NOW() - INTERVAL $days DAY",
            [$connId])->fetchAll();
        foreach ($old as $o) {
            try {
                $s3->delete($o['s3_key']);
                q("UPDATE dba_backups SET status = 'deleted' WHERE id = ?", [$o['id']]);
            } catch (Throwable) {
                // riprovera' al prossimo giro
            }
        }
    }

    /** Lancia il backup in background (GUI / MCP) senza bloccare la richiesta HTTP. */
    public static function spawn(int $connId, string $trigger): void
    {
        if (!function_exists('exec')) {
            throw new RuntimeException('exec() disabilitata in php.ini: lanciare il backup da riga di comando');
        }
        $php = (cfg()['backup']['php_bin'] ?? '') ?: 'php';
        exec(sprintf('nohup %s %s --connection=%d --trigger=%s > /dev/null 2>&1 &',
            escapeshellarg($php), escapeshellarg(realpath(APP_ROOT . '/bin/backup.php')), $connId, escapeshellarg($trigger)));
    }

    public static function history(?int $connId, int $limit = 50): array
    {
        $limit = max(1, min(500, $limit));
        return $connId
            ? q("SELECT * FROM dba_backups WHERE connection_id = ? ORDER BY id DESC LIMIT $limit", [$connId])->fetchAll()
            : q("SELECT * FROM dba_backups ORDER BY id DESC LIMIT $limit")->fetchAll();
    }
}

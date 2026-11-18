<?php
declare(strict_types=1);

/** Client S3 minimale (AWS Signature V4) senza dipendenze: AWS, Wasabi, Backblaze B2, MinIO, ecc. */
final class S3
{
    private string $host;
    private string $scheme;
    private string $basePath;

    public function __construct(private array $c)
    {
        foreach (['bucket', 'access_key', 'secret', 'region'] as $k) {
            if (($c[$k] ?? '') === '') {
                throw new RuntimeException("S3 non configurato: manca '$k' (GUI → Backup S3)");
            }
        }
        $endpoint = $c['endpoint'] ?: "https://s3.{$c['region']}.amazonaws.com";
        if (!preg_match('~^https?://~i', $endpoint)) {
            $endpoint = 'https://' . $endpoint;
        }
        $p = parse_url(rtrim($endpoint, '/'));
        $this->scheme = strtolower($p['scheme']);
        $host = $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
        if (!empty($c['path_style'])) {
            $this->host = $host;
            $this->basePath = '/' . $c['bucket'];
        } else {
            $this->host = $c['bucket'] . '.' . $host;
            $this->basePath = '';
        }
    }

    public function putFile(string $key, string $file): void
    {
        $size = filesize($file);
        if ($size === false) {
            throw new RuntimeException("File non leggibile: $file");
        }
        if ($size > 5 * 1024 ** 3) {
            throw new RuntimeException('Dump oltre 5 GB: supera il limite di un singolo PUT S3');
        }
        $fh = fopen($file, 'rb');
        try {
            // su HTTPS il corpo non viene firmato (evita di leggere due volte file di grandi dimensioni)
            $hash = $this->scheme === 'https' ? 'UNSIGNED-PAYLOAD' : hash_file('sha256', $file);
            $this->request('PUT', $key, $hash, [
                CURLOPT_UPLOAD     => true,
                CURLOPT_INFILE     => $fh,
                CURLOPT_INFILESIZE => $size,
                CURLOPT_TIMEOUT    => 6 * 3600,
            ], !empty($this->c['sse']) ? ['x-amz-server-side-encryption' => 'AES256'] : []);
        } finally {
            fclose($fh);
        }
    }

    public function putString(string $key, string $body): void
    {
        $this->request('PUT', $key, hash('sha256', $body), [
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS    => $body,
        ]);
    }

    public function delete(string $key): void
    {
        $this->request('DELETE', $key, hash('sha256', ''), [CURLOPT_CUSTOMREQUEST => 'DELETE']);
    }

    /** Verifica credenziali e permessi scrivendo e cancellando un oggetto di prova. */
    public function selfTest(): void
    {
        $key = trim(($this->c['prefix'] ?? '') . '/.dbadmin-test-' . bin2hex(random_bytes(4)), '/');
        $this->putString($key, 'test ' . gmdate('c'));
        $this->delete($key);
    }

    private function request(string $method, string $key, string $payloadHash, array $curlOpts, array $extraHeaders = []): void
    {
        $uri = $this->basePath . '/' . implode('/', array_map('rawurlencode', explode('/', ltrim($key, '/'))));
        $now = time();
        $amzDate = gmdate('Ymd\THis\Z', $now);
        $date = gmdate('Ymd', $now);
        $region = $this->c['region'];

        $headers = array_merge([
            'host'                 => $this->host,
            'x-amz-content-sha256' => $payloadHash,
            'x-amz-date'           => $amzDate,
        ], $extraHeaders);
        ksort($headers);
        $canonHeaders = '';
        foreach ($headers as $k => $v) {
            $canonHeaders .= $k . ':' . trim($v) . "\n";
        }
        $signed = implode(';', array_keys($headers));
        $canonical = "$method\n$uri\n\n$canonHeaders\n$signed\n$payloadHash";
        $scope = "$date/$region/s3/aws4_request";
        $toSign = "AWS4-HMAC-SHA256\n$amzDate\n$scope\n" . hash('sha256', $canonical);
        $k = hash_hmac('sha256', $date, 'AWS4' . $this->c['secret'], true);
        $k = hash_hmac('sha256', $region, $k, true);
        $k = hash_hmac('sha256', 's3', $k, true);
        $k = hash_hmac('sha256', 'aws4_request', $k, true);
        $sig = hash_hmac('sha256', $toSign, $k);

        $h = ["Authorization: AWS4-HMAC-SHA256 Credential={$this->c['access_key']}/$scope, SignedHeaders=$signed, Signature=$sig",
              'Expect:', 'Content-Type: application/octet-stream'];
        foreach ($headers as $name => $val) {
            if ($name !== 'host') {
                $h[] = "$name: $val";
            }
        }
        $ch = curl_init("{$this->scheme}://{$this->host}$uri");
        curl_setopt_array($ch, $curlOpts + [
            CURLOPT_HTTPHEADER     => $h,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT        => 60,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($body === false) {
            throw new RuntimeException("S3 $method: errore di rete: $err");
        }
        if ($code < 200 || $code >= 300) {
            $msg = preg_match('~<Code>(.*?)</Code>.*?<Message>(.*?)</Message>~s', (string)$body, $m) ? "$m[1]: $m[2]" : mb_substr((string)$body, 0, 300);
            throw new RuntimeException("S3 $method HTTP $code - $msg");
        }
    }
}

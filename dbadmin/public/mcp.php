<?php
declare(strict_types=1);
// Endpoint MCP (Streamable HTTP). URL da configurare nel client: https://TUO-DOMINIO/mcp.php
require __DIR__ . '/../src/bootstrap.php';

try {
    (new McpServer())->handleHttp();
} catch (Throwable $e) {
    error_log('[dbadmin-mcp] ' . $e->getMessage());
    http_response_code(500);
    header('Content-Type: application/json');
    echo '{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Errore interno del server"}}';
}

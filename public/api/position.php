<?php
declare(strict_types=1);
require __DIR__ . '/../../src/lib.php';

// POST /api/position.php  JSON {plate, lat, lng, accuracy}  -> salva su EG Auto
require_api_auth(true);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(['ok' => false, 'error' => 'Metodo non consentito'], 405);
}
$in = json_decode(file_get_contents('php://input') ?: '', true);
if (!is_array($in)) {
    json_out(['ok' => false, 'error' => 'JSON non valido'], 400);
}
$plate = normalize_plate((string)($in['plate'] ?? ''));
if (!plate_valid($plate) || !is_numeric($in['lat'] ?? null) || !is_numeric($in['lng'] ?? null)) {
    json_out(['ok' => false, 'error' => 'Parametri non validi'], 422);
}
try {
    $v = find_vehicle($plate);
    if (!$v) {
        json_out(['ok' => false, 'error' => 'Targa non trovata in EG Auto'], 404);
    }
    $acc = is_numeric($in['accuracy'] ?? null) ? (float)$in['accuracy'] : null;
    save_position($v[cfg()['egauto']['id_col']], (float)$in['lat'], (float)$in['lng'], $acc, 'web');
    json_out(['ok' => true, 'vehicle' => vehicle_public(find_vehicle($plate))]);
} catch (InvalidArgumentException $e) {
    json_out(['ok' => false, 'error' => $e->getMessage()], 422);
} catch (Throwable $e) {
    error_log($e->getMessage());
    json_out(['ok' => false, 'error' => 'Errore database'], 500);
}

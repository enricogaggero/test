<?php
declare(strict_types=1);
require __DIR__ . '/../../src/lib.php';

// GET /api/vehicle.php?plate=AB123CD  ->  scheda veicolo + ultima posizione
require_api_auth();
$plate = normalize_plate((string)($_GET['plate'] ?? ''));
if (!plate_valid($plate)) {
    json_out(['ok' => false, 'error' => 'Targa non valida'], 422);
}
try {
    $v = find_vehicle($plate);
} catch (Throwable $e) {
    error_log($e->getMessage());
    json_out(['ok' => false, 'error' => 'Errore database'], 500);
}
if (!$v) {
    json_out(['ok' => false, 'error' => 'Targa non trovata in EG Auto'], 404);
}
json_out(['ok' => true, 'vehicle' => vehicle_public($v)]);

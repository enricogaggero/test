<?php
declare(strict_types=1);
require __DIR__ . '/../../src/lib.php';

/*
 * Webhook Telegram. Flusso:
 *   1) l'utente scrive la targa  -> il bot risponde con pulsante "Invia posizione"
 *   2) l'utente invia la posizione (o la manda con didascalia = targa)
 *   -> lat/lng salvate su EG Auto (gps_source = 'telegram')
 * Registrazione:
 *   https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://TUO/telegram/webhook.php&secret_token=<webhook_secret>
 */
$t = cfg()['telegram'];
if (empty($t['enabled'])) { http_response_code(404); exit; }
if (!hash_equals((string)$t['webhook_secret'], $_SERVER['HTTP_X_TELEGRAM_BOT_API_SECRET_TOKEN'] ?? '')) {
    http_response_code(403); exit;
}

function tg(string $method, array $params): void
{
    $ch = curl_init('https://api.telegram.org/bot' . cfg()['telegram']['bot_token'] . '/' . $method);
    curl_setopt_array($ch, [
        CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode($params, JSON_UNESCAPED_UNICODE),
    ]);
    curl_exec($ch);
    curl_close($ch);
}

function reply(int $chat, string $text, ?array $markup = null): void
{
    $p = ['chat_id' => $chat, 'text' => $text];
    if ($markup) { $p['reply_markup'] = $markup; }
    tg('sendMessage', $p);
}

$u = json_decode(file_get_contents('php://input') ?: '', true);
$m = $u['message'] ?? null;               // le live-location (edited_message) sono ignorate
if (!$m) { http_response_code(200); exit; }

$chat = (int)$m['chat']['id'];
if (!in_array($chat, array_map('intval', $t['allowed_chats'] ?? []), true)) {
    reply($chat, "Chat non autorizzata (id $chat).");
    exit;
}

try {
    if (isset($m['location'])) {
        $plate = normalize_plate((string)($m['caption'] ?? ''));
        if ($plate === '') {
            $st = db()->prepare('SELECT plate FROM gps_telegram_state WHERE chat_id=? AND updated_at > NOW() - INTERVAL 15 MINUTE');
            $st->execute([$chat]);
            $plate = (string)($st->fetchColumn() ?: '');
        }
        if ($plate === '') {
            reply($chat, 'Prima scrivi la targa del veicolo.');
            exit;
        }
        $v = find_vehicle($plate);
        if (!$v) { reply($chat, "Targa $plate non trovata."); exit; }
        $loc = $m['location'];
        save_position($v[cfg()['egauto']['id_col']], (float)$loc['latitude'], (float)$loc['longitude'],
            isset($loc['horizontal_accuracy']) ? (float)$loc['horizontal_accuracy'] : null, 'telegram');
        db()->prepare('DELETE FROM gps_telegram_state WHERE chat_id=?')->execute([$chat]);
        reply($chat, sprintf("✅ Posizione di %s salvata: %.6f, %.6f", $plate, $loc['latitude'], $loc['longitude']),
            ['remove_keyboard' => true]);
        exit;
    }

    $plate = normalize_plate((string)($m['text'] ?? ''));
    if (!plate_valid($plate)) { reply($chat, 'Scrivi una targa valida (es. AB123CD).'); exit; }
    if (!find_vehicle($plate)) { reply($chat, "Targa $plate non trovata in EG Auto."); exit; }
    db()->prepare('REPLACE INTO gps_telegram_state (chat_id, plate, updated_at) VALUES (?,?,NOW())')
        ->execute([$chat, $plate]);
    reply($chat, "Targa $plate trovata. Tocca il pulsante per inviare la posizione.", [
        'keyboard' => [[['text' => '📍 Invia posizione', 'request_location' => true]]],
        'resize_keyboard' => true, 'one_time_keyboard' => true,
    ]);
} catch (Throwable $e) {
    error_log($e->getMessage());
    reply($chat, 'Errore interno, riprova.');
}
http_response_code(200);

<?php
/**
 * Plisio Callback / Webhook Endpoint - En Güvenli Versiyon
 *
 * Güvenlik katmanları:
 * 1. Sadece Plisio IP'sinden kabul et (216.219.89.38)
 * 2. POST + geçerli JSON
 * 3. Gerekli alanlar kontrolü
 * 4. verify_hash HMAC-SHA1 doğrulaması (timing-safe)
 * 5. Aynı invoice_id ile tekrar işlem yapmama
 * 6. Tutar & para birimi tutarlılık kontrolü
 */

// database bağlantısı ve gerekirse oturum (hash log için)
require_once __DIR__ . '/../database.php';
session_start();

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');

// --------------- 1. IP Whitelist (EN KRİTİK GÜVENLİK) ---------------
$allowed_ips = ['216.219.89.38'];

$client_ip = $_SERVER['REMOTE_ADDR'];
// Cloudflare varsa gerçek IP için:
if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
    $client_ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
}
if (!in_array($client_ip, $allowed_ips, true)) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized IP address']);
    exit;
}
// --------------- 2. Method ve Input Kontrolü ---------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']);
    exit;
}
$rawInput = file_get_contents('php://input');
if (empty($rawInput)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Empty payload']);
    exit;
}
$data = json_decode($rawInput, true);
if (json_last_error() !== JSON_ERROR_NONE || !is_array($data)) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid JSON']);
    exit;
}
// --------------- 3. Zorunlu Alanlar ---------------
$required_fields = ['status', 'order_name', 'invoice_id', 'amount', 'currency', 'psys_cid', 'txn_id', 'verify_hash'];
foreach ($required_fields as $field) {
    if (!isset($data[$field]) || $data[$field] === '') {
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => "Missing or empty field: $field"]);
        exit;
}
}

// --------------- 4. Secret Key ve Hash Doğrulama ---------------
$secret_key = getenv('PLISIO_SECRET_KEY') ?: '';  // .env veya server config'den çek
if (empty($secret_key)) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Server configuration error']);
    exit;
}
// Hash hesapla (Plisio standart yöntemi)
$to_verify = $data;
unset($to_verify['verify_hash']);
ksort($to_verify);

// http_build_query ile daha temiz ve standart string oluştur
$verify_string = http_build_query($to_verify, '', '&');
$expected_hash = hash_hmac('sha1', $verify_string, $secret_key);

if (!hash_equals($expected_hash, $data['verify_hash'])) {
    http_response_code(403);
    echo json_encode(['status' => 'error', 'message' => 'Invalid signature']);
    exit;
}
// --------------- 5. Duplicate İşlem Kontrolü (Replay Attack Önleme) ---------------
// invoice_id daha önce zorunlu alanlar içinde garantilendi
$invoice_id = $data['invoice_id'];
$status     = $data['status'];

// veritabanında aynı invoice_id ile daha önce işlem yapılmış mı ?
$stmt = $db->prepare("SELECT COUNT(*) FROM jetonkod WHERE invoice_id = ?");
$stmt->bind_param('s', $invoice_id);
$stmt->execute();
$stmt->bind_result($cnt);
$stmt->fetch();
$stmt->close();

if ($cnt > 0) {
    // tekrar eden webhook, sorunsuz bir cevap dön
    http_response_code(200);
    echo json_encode(['status' => 'ok', 'message' => 'Duplicate invoice']);
    exit;
}
// --------------- 6. order_name Parse + Tutar Doğrulama ---------------
$orderParts = array_map('trim', explode('|', $data['order_name']));
if (count($orderParts) < 2) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid order_name format']);
    exit;
}
$telegram_id_str = $orderParts[1];
$telegramId = (int) filter_var($telegram_id_str, FILTER_VALIDATE_INT);

if ($telegramId <= 0) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid telegram_id in order_name']);
    exit;
}
$received_amount = floatval($data['amount']);
$received_currency = strtoupper($data['currency']);

$expected_amount = 0;
$is_code_order = false;

if (strtoupper($orderParts[1]) === 'CODE') {
    // CODE|CODE|telegramId|amount  formatı varsayılıyor
    $is_code_order = true;
    $expected_amount = floatval($orderParts[3] ?? $received_amount);
}
else {
    // Normal: telegramId|amount
    $expected_amount = floatval($orderParts[2] ?? $received_amount);
}
// Tutar ve para birimi kontrolü (küçük farklara tolerans)
if (abs($expected_amount - $received_amount) > 0.01 || $received_currency !== 'TL') {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Amount or currency mismatch']);
    exit;
}
// --------------- 8. İş Mantığı ---------------
$amount = $received_amount; // güvenilir kaynak olarak callback'ten alıyoruz (kontrollerden geçti)

$epin = 'PLISIO-' . bin2hex(random_bytes(4)); // veya daha uzun/özel format

if ($is_code_order) {
    // CODE siparişi → tek kullanımlık E-PIN oluştur
    $epinRaw = bin2hex(random_bytes(8));
    $epin = strtoupper(implode('-', str_split($epinRaw, 4)));

    $stmt = $db->prepare("
        INSERT INTO jetonkod
        (`key`, jeton, type, used, created_at, telegram_id, invoice_id, amount_plisio, currency)
        VALUES (?, ?, 'code', 0, NOW(), ?, ?, ?, ?)
    ");
    $stmt->bind_param('ssisss', $epin, $amount, $telegramId, $invoice_id, $amount, $received_currency);
    $stmt->execute();
    $stmt->close();

    // Telegram bildirimi
    $botToken = $telegram_bot_token ?? '';
    if ($botToken !== '') {
        $msg = "🎫 CODE Siparişiniz Oluşturuldu!\n\n" .
               "💰 Tutar: {$amount} TL\n" .
               "E-PIN Kodunuz: <code>{$epin}</code>";
        $url = "https://api.telegram.org/bot{$botToken}/sendMessage?" . http_build_query([
            'chat_id' => $telegramId,
            'text' => $msg,
            'parse_mode' => 'HTML'
        ]);
        @file_get_contents($url);
}
echo json_encode(['status' => 'ok', 'message' => 'Code created']);
}
else {
    // Normal bakiye yükleme
    $stmt = $db->prepare("UPDATE accounts SET balance = balance + ? WHERE telegram_id = ?");
    $stmt->bind_param('di', $amount, $telegramId);
    $stmt->execute();
    $stmt->close();

    $stmt = $db->prepare("
        INSERT INTO jetonkod
        (`key`, jeton, type, used, created_at, telegram_id, invoice_id, amount_plisio, currency)
        VALUES (?, ?, 'plisio', 0, NOW(), ?, ?, ?, ?)
    ");
    $stmt->bind_param('ssisss', $epin, $amount, $telegramId, $invoice_id, $amount, $received_currency);
    $stmt->execute();
    $stmt->close();

    // Telegram bildirimi
    $botToken = $telegram_bot_token ?? '';
    if ($botToken !== '') {
        $msg = "💳 Ödemeniz başarıyla tamamlandı!\n" .
               "💰 Tutar: {$amount} TL\n" .
               "Mevcut bakiyeniz güncellendi.";
        $url = "https://api.telegram.org/bot{$botToken}/sendMessage?" . http_build_query([
            'chat_id' => $telegramId,
            'text' => $msg
        ]);
        @file_get_contents($url);
}
echo json_encode(['status' => 'ok', 'message' => 'Balance updated']);
}

// --------------- 9. Ödeme kaydı (success log) ---------------
$logMeta = [
    'order_name' => $data['order_name'],
    'psys_cid'   => $data['psys_cid'] ?? null,
    'txn_id'     => $data['txn_id'] ?? null,
    'type'       => $is_code_order ? 'code' : 'plisio',
    'ip'         => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
];
logPlisioPayment($db, $invoice_id, $amount, $logMeta);

exit;

// --------------- ÖDEME LOG FONKSİYONU ---------------
function logPlisioPayment(PDO $db, string $hash, float $tutar, array $meta)
{
    try {
        $stmt = $db->prepare("
            INSERT INTO payments
            (hash, odeme_yontemi, tarih, durum, tutar, meta)
            VALUES
            (:hash, 3, NOW(), 1, :tutar, :meta)
        ");
        $stmt->execute([
            ':hash'  => $hash,
            ':tutar' => $tutar,
            ':meta'  => json_encode($meta, JSON_UNESCAPED_UNICODE)
        ]);
    } catch (Exception $e) {
        error_log('Plisio log error: ' . $e->getMessage());
    }
}


<?php
declare(strict_types=1);

require_once '../../database.php';
session_start();

// ======================================================
// IP KONTROL
// ======================================================
$valid_ips = [
    '144.202.124.62','144.202.124.63','144.202.124.64','144.202.124.65',
    '170.64.150.100','170.64.150.101','170.64.150.102','170.64.150.103'
];

if (!in_array($_SERVER['REMOTE_ADDR'], $valid_ips, true)) {
    http_response_code(403);
    exit('Forbidden');
}
// ======================================================
// PAYLOAD + SIGNATURE
// ======================================================
$payload = file_get_contents('php://input');
if (!$payload) {
    http_response_code(400);
    exit('Empty payload');
}
$signature = $_SERVER['HTTP_X_SIGNATURE'] ?? '';
$cripto_password = $db->query("SELECT cripto_password FROM settings LIMIT 1")->fetchColumn();

if (
    !$cripto_password ||
    !hash_equals(hash_hmac('sha256', $payload, $cripto_password), $signature)
) {
    http_response_code(401);
    exit('Invalid signature');
}
$data = json_decode($payload, true);
if (!is_array($data)) {
    http_response_code(400);
    exit('Invalid JSON');
}
// ======================================================
// SADECE PAID
// ======================================================
if (($data['data']['status'] ?? '') !== 'PAID') {
    http_response_code(200);
    exit('Ignored');
}
// ======================================================
// TOKEN + SESSION
// ======================================================
$token = $data['data']['custom_data1'] ?? null;

if (
    !$token ||
    empty($_SESSION['pending_invoice'][$token])
) {
    http_response_code(200);
    exit('Invalid token');
}
// çekilen token üzerinden fatura verisini al ve doğrula
$invoice = $_SESSION['pending_invoice'][$token] ?? null;
if (!is_array($invoice)) {
    http_response_code(200);
    exit('Invalid token');
}

// 15 dk timeout
if ((time() - ($invoice['created_at'] ?? 0)) > 900) {
    unset($_SESSION['pending_invoice'][$token]);
    http_response_code(200);
    exit('Expired');
}
// ======================================================
// TUTAR
// ======================================================
$final_amount = round(
    (float)($data['data']['total_amount_try'] ?? 0),
    2
);

$username_safe = $invoice['username'] ?? null;

if ($final_amount <= 0 || !$username_safe) {
    unset($_SESSION['pending_invoice'][$token]);
    http_response_code(200);
    exit('Corrupted');
}
// ======================================================
// BAKİYE EKLE + SUCCESS LOG
// ======================================================
try {
    $db->beginTransaction();

    $username_b64 = base64_encode($username_safe);

    $stmt = $db->prepare("
        UPDATE accounts
        SET balance = balance + :amount
        WHERE username = :username
    ");
    $stmt->execute([
        ':amount'   => $final_amount,
        ':username' => $username_b64
    ]);

    if ($stmt->rowCount() === 0) {
        throw new Exception('User not found');
}
// SADECE SUCCESS LOG
    logSuccessPayment(
        $db,
        $_SESSION['GET_USER_SSID'] ?? 'system',
        $final_amount,
        $data
    );

    $db->commit();
    unset($_SESSION['pending_invoice'][$token]);

    http_response_code(200);
    exit('OK');
}
catch (Exception $e) {
    $db->rollBack();
    error_log('Crypto webhook error: ' . $e->getMessage());
    http_response_code(500);
    exit('Error');
}
// ======================================================
// SUCCESS LOG FONKSİYONU (TEK LOG)
// ======================================================
function logSuccessPayment(
    PDO $db,
    string $hash,
    float $tutar,
    array $data
) {
    $meta = [
        'source'         => 'coinremitter',
        'token'          => $token,
        'username'       => $invoice['username'] ?? null,
        'invoice_id'     => $data['data']['invoice_id'] ?? null,
        'coin'           => $data['data']['coin'] ?? 'BTC',
        'amount_try'     => $data['data']['amount_try'] ?? null,
        'total_paid_try' => $data['data']['total_amount_try'] ?? null,
        'fee_try'        => $data['data']['fee_try'] ?? null,
        'ip'             => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
    ];

    $stmt = $db->prepare("
        INSERT INTO payments
        (hash, odeme_yontemi, tarih, durum, tutar, meta)
        VALUES
        (:hash, 1, NOW(), 1, :tutar, :meta)
    ");

    $stmt->execute([
        ':hash'  => $hash,
        ':tutar' => $tutar,
        ':meta'  => json_encode($meta, JSON_UNESCAPED_UNICODE)
    ]);
}


<?php
require_once '../../database.php';
include '../../webhook.php';
session_start();

header('Content-Type: application/json; charset=utf-8');

// =====================================================
// OTURUM
// =====================================================
$hash = $_SESSION['GET_USER_SSID'] ?? null;
$odeme_tur = 2; // Jeton
$logger = new WebhookLoggerPlain($discordWebhooks, $TELEGRAM_BOT_TOKEN, $TELEGRAM_CHAT_MAP);

if (!$hash) {
    echo json_encode([
        'status' => 'error',
        'message' => 'Kullanıcı oturumu bulunamadı'
    ]);
    exit;
}
// =====================================================
// INPUT
// =====================================================
$username = trim($_POST['username'] ?? '');
$key      = trim($_POST['key'] ?? '');

if ($username === '' || $key === '') {
    echo json_encode([
        'status' => 'error',
        'message' => 'Eksik bilgi gönderildi'
    ]);
    exit;
}
// =====================================================
// JETON KOD KONTROL
// =====================================================
$stmt = $db->prepare("SELECT jeton FROM jetonkod WHERE `key` = :key LIMIT 1");
$stmt->execute([':key' => $key]);
$kodData = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$kodData) {
    echo json_encode([
        'status' => 'error',
        'message' => '❌ Geçersiz veya kullanılmış jeton kodu'
    ]);
    exit;
}
$jeton = (float)$kodData['jeton'];
$username_base64 = base64_encode($username);

// =====================================================
// BAKİYE EKLE + SUCCESS LOG
// =====================================================
try {
    $db->beginTransaction();

    $update = $db->prepare("
        UPDATE accounts
        SET balance = balance + :jeton
        WHERE username = :username
    ");
    $update->execute([
        ':jeton'    => $jeton,
        ':username' => $username_base64
    ]);

    if ($update->rowCount() === 0) {
        throw new Exception('Kullanıcı bulunamadı');
}
// KODU SİL
    $delete = $db->prepare("DELETE FROM jetonkod WHERE `key` = :key");
    $delete->execute([':key' => $key]);

    // SADECE SUCCESS LOG
    logSuccessJeton(
        $db,
        $hash,
        $odeme_tur,
        $jeton,
        $key
    );

    $db->commit();
    
    $logger->sendLog([
            'hook'            => 'bayi',
            'chat'            => 'log',
            'discordEnabled'  => true,
            'telegramEnabled' => true,
            'level'           => 'success',
            'title'           => 'Jeton Kodu Kulanıldı',
            'fields'          => [
                ['name'=>'Kulanan Kullanıcı','value'=>$username],
                ['name'=>'Kulanılan Kod','value'=>$key],
                ['name'=>'Eklenen Bakye','value'=>$jeton]
            ],
            'show_date'       => false,
        ]);

    echo json_encode([
        'status'  => 'success',
        'message' => "✅ {$jeton} TL başarıyla hesabınıza eklendi"
    ]);
    exit;
}
catch (Exception $e) {
    $db->rollBack();
    error_log('Jeton error: ' . $e->getMessage());

    echo json_encode([
        'status' => 'error',
        'message' => 'İşlem başarısız'
    ]);
    exit;
}
// =====================================================
// SUCCESS LOG FONKSİYONU (TEK LOG, HASH TEK)
// =====================================================
function logSuccessJeton(
    PDO $db,
    string $hash,
    int $odeme_tur,
    float $tutar,
    string $key
) {
    try {
        $meta = [
            'type' => 'jeton',
            'key'  => $key
        ];

        $stmt = $db->prepare("
            INSERT INTO payments
            (hash, odeme_yontemi, tarih, durum, tutar, meta)
            VALUES
            (:hash, :yontem, NOW(), 1, :tutar, :meta)
        ");

        $stmt->execute([
            ':hash'   => $hash,
            ':yontem' => $odeme_tur,
            ':tutar'  => $tutar,
            ':meta'   => json_encode($meta, JSON_UNESCAPED_UNICODE)
        ]);
}
catch (Exception $e) {
        error_log('Payment log error: ' . $e->getMessage());
}
}

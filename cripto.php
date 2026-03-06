<?php
// DOSYA: pay/crypto.php
declare(strict_types=1);

// ÇIKTIYI ENGELLE
ob_start();
session_start();

require_once '../../database.php';

// OTURUM KONTROL
if (empty($_SESSION['GET_USER_SSID'])) {
    die('Oturum hatası');
}
$hash = $_SESSION['GET_USER_SSID'];

// AYARLAR
$settings = $db->query("
    SELECT cripto_api_key, cripto_password, site_domain
    FROM settings
    LIMIT 1
")->fetch(PDO::FETCH_ASSOC);

if (!$settings || empty($settings['cripto_api_key'])) {
    die('Kripto ayarları eksik');
}
$site_domain = rtrim($settings['site_domain'], '/');

// POST KONTROL
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    die('Geçersiz istek');
}
// INPUT
$amount_tryy = round((float)str_replace([' ', ','], ['', '.'], $_POST['amount'] ?? '0'), 2);

$amount_try = round($amount_tryy * 1.01, 2);
$username   = trim($_POST['username'] ?? '');

if ($amount_try < 5) die('Minimum 5 TL');
if ($amount_try > 100000) die('Maksimum 100.000 TL');
if ($username === '' || strlen($username) > 30) die('Kullanıcı adı hatalı');

// USERNAME TEMİZLEME
$username_safe = preg_replace(
    '/[^A-Za-z0-9._-]/',
    '',
    strtr($username, [
        'ç'=>'c','Ç'=>'C','ğ'=>'g','Ğ'=>'G','ı'=>'i','İ'=>'I',
        'ö'=>'o','Ö'=>'O','ş'=>'s','Ş'=>'S','ü'=>'u','Ü'=>'U'
    ])
);

// FATURA TOKEN
$invoice_token = bin2hex(random_bytes(16));

$_SESSION['pending_invoice'][$invoice_token] = [
    'username'   => $username_safe,
    'amount_try' => $amount_try,
    'created_at' => time(),
    'ip'         => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
];

// COINREMITTER DATA
$postData = [
    'amount'        => $amount_try,
    'fiat_currency' => 'TRY',
    'wallet_name'   => 'BTC',
    'name'          => $username_safe,
    'notify_url'    => $site_domain . '/pay/control/crypto',
    'success_url'   => $site_domain . '/pay/success',
    'fail_url'      => $site_domain . '/pay/error',
    'expire_time'   => 15,
    'description'   => 'Deposit',
    'custom_data1'  => $invoice_token
];

// CURL
$ch = curl_init();
curl_setopt_array($ch, [
    CURLOPT_URL            => 'https://api.coinremitter.com/v1/invoice/create',
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => http_build_query($postData),
    CURLOPT_HTTPHEADER     => [
        'x-api-key: ' . $settings['cripto_api_key'],
        'x-api-password: ' . $settings['cripto_password'],
        'Content-Type: application/x-www-form-urlencoded'
    ],
    CURLOPT_TIMEOUT        => 30,
    CURLOPT_SSL_VERIFYPEER => true,
]);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// SADECE BAŞARILI FATURADA DEVAM
if ($httpCode === 200) {
    $result = json_decode($response, true);

    if (!empty($result['success']) && $result['success'] === true) {

        $redirect_url =
            $result['data']['url']
            ?? $result['data']['payment_url']
            ?? null;

        if ($redirect_url) {

            // KOMİSYON (%3 örnek)
            $commission_rate = 0.03;
            $net_amount = round(
                $amount_try - ($amount_try * $commission_rate),
                2
            );

            // LOG (SADECE FATURA OLUŞTUYSA)
            try {
                $stmt = $db->prepare("
                    INSERT INTO payments
                    (hash, odeme_yontemi, durum, tutar, url, tarih)
                    VALUES
                    (?, 1, 0, ?, ?, NOW())
                ");
                $stmt->execute([
                    $hash,
                    $amount_tryy,
                    $redirect_url
                ]);
}
catch (Exception $e) {
                // sessiz geç
}
ob_end_clean();
            header('Location: ' . $redirect_url);
            exit;
}
}
}
// HATA → LOG YOK
ob_end_clean();
$_SESSION['payment_error'] = 'Fatura oluşturulamadı';
header('Location: ' . $site_domain . '/pay/error');
exit;

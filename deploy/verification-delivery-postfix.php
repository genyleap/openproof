<?php
declare(strict_types=1);

header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function failRequest(int $status): never
{
    http_response_code($status);
    exit;
}

function envValue(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false ? $default : trim((string)$value);
}

function safeHeaderValue(string $value): bool
{
    return $value !== '' && !preg_match('/[\r\n]/', $value);
}

function configuredUrl(string $name): string
{
    $value = envValue($name);
    if (!safeHeaderValue($value) || filter_var($value, FILTER_VALIDATE_URL) === false) {
        failRequest(503);
    }
    $parts = parse_url($value);
    if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https') {
        failRequest(503);
    }
    return rtrim($value, '?&');
}

function smtpRead($socket, array $expected): bool
{
    do {
        $line = fgets($socket, 4096);
        if ($line === false) {
            return false;
        }
    } while (strlen($line) >= 4 && $line[3] === '-');
    return in_array((int)substr($line, 0, 3), $expected, true);
}

function smtpCommand($socket, string $command, array $expected): bool
{
    if (fwrite($socket, $command . "\r\n") === false) {
        return false;
    }
    return smtpRead($socket, $expected);
}

$remote = (string)($_SERVER['REMOTE_ADDR'] ?? '');
if ($remote !== '127.0.0.1' && $remote !== '::1') {
    failRequest(403);
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
    || ($_SERVER['REQUEST_URI'] ?? '') !== '/v1/openproof/verification') {
    failRequest(404);
}

$tokenFile = envValue(
    'OPENPROOF_DELIVERY_TOKEN_FILE',
    '/run/openproof/secrets/verification-webhook.token'
);
$expected = trim((string)@file_get_contents($tokenFile));
$received = (string)($_SERVER['HTTP_AUTHORIZATION'] ?? '');
if ($expected === '' || !hash_equals('Bearer ' . $expected, $received)) {
    failRequest(403);
}

$length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
if ($length <= 0 || $length > 16384) {
    failRequest(413);
}
$raw = (string)file_get_contents('php://input');
if (strlen($raw) > 16384) {
    failRequest(413);
}
try {
    $payload = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
} catch (JsonException) {
    failRequest(400);
}
if (!is_array($payload)) {
    failRequest(400);
}

$required = [
    'verification_id',
    'identity_id',
    'purpose',
    'channel',
    'destination',
    'secret',
];
foreach ($required as $key) {
    if (!isset($payload[$key]) || !is_string($payload[$key]) || $payload[$key] === '') {
        failRequest(400);
    }
}

if ($payload['channel'] !== 'email'
    || filter_var($payload['destination'], FILTER_VALIDATE_EMAIL) === false) {
    failRequest(422);
}

$purpose = $payload['purpose'];
$targets = [
    'signup_email' => 'OPENPROOF_DELIVERY_SIGNUP_URL',
    'change_email' => 'OPENPROOF_DELIVERY_CHANGE_EMAIL_URL',
    'password_reset' => 'OPENPROOF_DELIVERY_PASSWORD_RESET_URL',
];
if (!isset($targets[$purpose])) {
    failRequest(422);
}

$urlVariable = $targets[$purpose];
$actionUrl = configuredUrl($urlVariable);
$queryParams = [
    'id' => $payload['verification_id'],
    'secret' => $payload['secret'],
];
if ($purpose === 'change_email') {
    $queryParams['identity'] = $payload['identity_id'];
}
$query = http_build_query(
    $queryParams,
    '',
    '&',
    PHP_QUERY_RFC3986
);
$actionUrl .= (str_contains($actionUrl, '?') ? '&' : '?') . $query;

$mailFrom = envValue('OPENPROOF_DELIVERY_FROM');
$brand = envValue('OPENPROOF_DELIVERY_BRAND', 'OpenProof');
$smtpHost = envValue('OPENPROOF_DELIVERY_SMTP_HOST', '127.0.0.1');
$smtpPort = (int)envValue('OPENPROOF_DELIVERY_SMTP_PORT', '25');
if (filter_var($mailFrom, FILTER_VALIDATE_EMAIL) === false
    || !safeHeaderValue($mailFrom)
    || preg_match('/^[A-Za-z0-9 ._-]{1,80}$/', $brand) !== 1
    || !in_array($smtpHost, ['127.0.0.1', '::1'], true)
    || $smtpPort < 1 || $smtpPort > 65535) {
    failRequest(503);
}
$subjects = [
    'signup_email' => $brand . ': verify your account',
    'change_email' => $brand . ': confirm your email',
    'password_reset' => $brand . ': reset your password',
];
$intro = [
    'signup_email' => 'Verify your account with this one-time link:',
    'change_email' => 'Confirm your new email address with this one-time link:',
    'password_reset' => 'Choose a new password with this one-time link:',
];

$body = $intro[$purpose] . "\r\n\r\n"
    . $actionUrl
    . "\r\n\r\nIf you did not request this action, ignore this email."
    . "\r\n\r\n" . $brand . "\r\n";

$headers = [
    'From: ' . $brand . ' <' . $mailFrom . '>',
    'To: ' . $payload['destination'],
    'Subject: ' . $subjects[$purpose],
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    'Auto-Submitted: auto-generated',
    'X-Auto-Response-Suppress: All',
];
$message = implode("\r\n", $headers) . "\r\n\r\n" . $body;

$errno = 0;
$errstr = '';
$socket = @fsockopen($smtpHost, $smtpPort, $errno, $errstr, 5.0);
if (!is_resource($socket)) {
    failRequest(502);
}
stream_set_timeout($socket, 5);

$accepted = smtpRead($socket, [220])
    && smtpCommand($socket, 'EHLO openproof-delivery.local', [250])
    && smtpCommand($socket, 'MAIL FROM:<' . $mailFrom . '>', [250])
    && smtpCommand($socket, 'RCPT TO:<' . $payload['destination'] . '>', [250, 251])
    && smtpCommand($socket, 'DATA', [354]);

if ($accepted) {
    $wire = (string)preg_replace('/(?m)^\./', '..', $message);
    $wire = rtrim($wire, "\r\n") . "\r\n.\r\n";
    $accepted = fwrite($socket, $wire) !== false && smtpRead($socket, [250]);
}

smtpCommand($socket, 'QUIT', [221]);
fclose($socket);
if (!$accepted) {
    failRequest(502);
}
http_response_code(204);

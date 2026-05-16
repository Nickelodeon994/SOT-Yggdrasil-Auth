<?php

/**
 * SOT Yggdrasil Auth
 * 
 * @version 0.0.2
 * @build 2026-05-16
 * @author Nickelodeon994
 * @link https://github.com/Nickelodeon994/SOT-Yggdrasil-Auth
 * @license Apache-2.0
 * 
 * 更新日志：
 * - 0.0.1 (2026-05-15) 初始版本
 *   * 用户系统
 *   * 皮肤系统
 *   * 安全机制
 *   * 后台管理
 * - 0.0.2 (2026-05-16)
 *   * 浅色/深色模式适配
 *   * 注册/登录时间窗口限制
 *   * 精简版人机验证
 *   * 新增更多后台配置项
 */


/**
 * Copyright 2026 Nickelodeon994
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


session_start();

define('DATA_DIR', __DIR__ . '/data');
if (!is_dir(DATA_DIR)) @mkdir(DATA_DIR, 0755, true);

function log_write($message) {
    $logFile = DATA_DIR . '/error.log';
    $maxSize = 2 * 1024 * 1024;
    $exists = file_exists($logFile);
    $size = $exists ? @filesize($logFile) : 0;
    if ($exists && $size > $maxSize) {
        @file_put_contents($logFile, date('Y-m-d H:i:s') . " [日志覆盖] 旧日志超过2MB，已清空\n");
    } else {
        @file_put_contents($logFile, $message, FILE_APPEND);
    }
}

log_write(date('Y-m-d H:i:s') . " Script start\n");
set_error_handler(function($errno, $errstr, $errfile, $errline) {
    log_write(date('Y-m-d H:i:s') . " ERR[$errno] $errstr in $errfile:$errline\n");
    return false;
});
set_exception_handler(function($e) {
    log_write(date('Y-m-d H:i:s') . " EXC: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine() . "\n");
});

header_remove('X-Powered-By');
ini_set('expose_php', 'Off');
error_reporting(E_ALL);
ini_set('display_errors', '0');

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data: *; connect-src 'self'");

define('USERS_DIR', DATA_DIR . '/users');
define('SKINS_DIR', DATA_DIR . '/skins');
define('USERNAMES_DIR', DATA_DIR . '/usernames');
define('AVATARS_DIR', DATA_DIR . '/avatars');
define('RATELIMIT_DIR', DATA_DIR . '/ratelimit');

define('MAX_SKIN_SIZE', 100 * 1024);
define('MAX_AVATAR_SIZE', 2 * 1024 * 1024);
define('TOKEN_TTL', 86400);
define('VERSION', '0.0.2');

function init_data_dir() {
    $dirs = [DATA_DIR, USERS_DIR, SKINS_DIR, USERNAMES_DIR, AVATARS_DIR, RATELIMIT_DIR];
    foreach ($dirs as $d) {
        if (!is_dir($d)) @mkdir($d, 0755, true);
    }

    $settings_file = DATA_DIR . '/settings.json';
    $defaults = [
        'server_name' => 'SOT Auth Server',
        'allow_register' => true,
        'uuid_algorithm' => 'offline',
        'site_logo' => '',
        'site_favicon' => '',
        'register_time_start' => '',
        'register_time_end' => '',
        'login_time_start' => '',
        'login_time_end' => '',
        'register_rate_limit' => 5,
        'register_rate_window' => 900,
        'login_rate_limit' => 5,
        'login_rate_window' => 900,
        'require_captcha_register' => false,
        'require_captcha_login' => false,
        'trust_proxy' => false
    ];
    if (!file_exists($settings_file)) {
        file_put_contents($settings_file, json_encode($defaults, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    } else {
        $settings = json_read($settings_file, []);
        $updated = false;
        foreach ($defaults as $k => $v) {
            if (!array_key_exists($k, $settings)) {
                $settings[$k] = $v;
                $updated = true;
            }
        }
        if ($updated) {
            json_write($settings_file, $settings);
        }
    }

    $counter_file = DATA_DIR . '/uid_counter.txt';
    if (!file_exists($counter_file)) {
        file_put_contents($counter_file, '10000');
    }

    $htaccess = DATA_DIR . '/.htaccess';
    if (!file_exists($htaccess)) {
        @file_put_contents($htaccess, "Options -Indexes\nDeny from all\n");
    }
}

init_data_dir();

function json_read($path, $default = null) {
    if (!file_exists($path)) return $default;
    $content = file_get_contents($path);
    if ($content === false) return $default;
    $data = json_decode($content, true);
    return $data !== null ? $data : $default;
}

function json_write($path, $data) {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $tmp = $path . '.tmp.' . uniqid();
    file_put_contents($tmp, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
    rename($tmp, $path);
    @chmod($path, 0644);
    return true;
}

function sanitize($s) {
    return preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $s);
}

function generate_uid() {
    $counter_file = DATA_DIR . '/uid_counter.txt';
    $fp = fopen($counter_file, 'c+');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    $counter = intval(trim(fgets($fp))) ?: 10000;
    $counter++;
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, strval($counter));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return $counter;
}

function generate_token() {
    return bin2hex(random_bytes(32));
}

function get_client_ip() {
    $settings = json_read(DATA_DIR . '/settings.json', []);
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    if (!empty($settings['trust_proxy']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded_ips = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
        $candidate = end($forwarded_ips);
        if (filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            $ip = $candidate;
        }
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function json_response($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function error($message, $code = 400) {
    json_response(['success' => false, 'message' => $message], $code);
}

function success($data = []) {
    json_response(array_merge(['success' => true], $data));
}

function require_login() {
    if (empty($_SESSION['uid'])) {
        error('请先登录', 401);
    }
}

function require_admin() {
    require_login();
    $profile = get_user_profile($_SESSION['uid']);
    if (!$profile || ($profile['role'] ?? '') !== 'admin') {
        error('权限不足', 403);
    }
    if ($_SESSION['role'] !== 'admin') {
        $_SESSION['role'] = 'admin';
    }
}

function get_current_uid() {
    return $_SESSION['uid'] ?? null;
}

function ensure_csrf() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf() {
    $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        error('安全验证失败，请刷新页面后重试', 403);
    }
}

function check_rate_limit($key, $maxAttempts = 5, $window = 900) {
    $file = RATELIMIT_DIR . '/' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $key) . '.json';
    $now = time();
    $data = json_read($file, ['attempts' => 0, 'first_attempt' => 0, 'locked_until' => 0]);
    if ($data['locked_until'] > $now) {
        $wait = ceil(($data['locked_until'] - $now) / 60);
        error('请求过于频繁，请 ' . $wait . ' 分钟后再试', 429);
    }
    if ($now - $data['first_attempt'] > $window) {
        $data = ['attempts' => 1, 'first_attempt' => $now, 'locked_until' => 0];
    } else {
        $data['attempts']++;
        if ($data['attempts'] >= $maxAttempts) {
            $data['locked_until'] = $now + $window;
            json_write($file, $data);
            error('请求过于频繁，已锁定 ' . ceil($window / 60) . ' 分钟', 429);
        }
    }
    json_write($file, $data);
    return true;
}

function is_in_time_window($start, $end) {
    if (empty($start) || empty($end)) return true;
    $now = date('H:i');
    if ($start <= $end) {
        return $now >= $start && $now <= $end;
    }
    return $now >= $start || $now <= $end;
}

function generate_captcha() {
    $ops = ['+', '-', '*'];
    $op = $ops[array_rand($ops)];
    if ($op === '+') {
        $a = rand(3, 30);
        $b = rand(2, 20);
        $ans = $a + $b;
    } elseif ($op === '-') {
        $a = rand(10, 40);
        $b = rand(2, $a - 1);
        $ans = $a - $b;
    } else {
        $a = rand(2, 12);
        $b = rand(2, 12);
        $ans = $a * $b;
    }
    $question = "{$a} {$op} {$b} = ?";
    $_SESSION['captcha_answer'] = (string)$ans;
    $_SESSION['captcha_time'] = time();
    return $question;
}

function verify_captcha($answer) {
    if (empty($_SESSION['captcha_answer']) || empty($_SESSION['captcha_time'])) {
        return false;
    }
    if (time() - $_SESSION['captcha_time'] > 300) {
        unset($_SESSION['captcha_answer'], $_SESSION['captcha_time']);
        return false;
    }
    $ok = trim($answer) === (string)$_SESSION['captcha_answer'];
    unset($_SESSION['captcha_answer'], $_SESSION['captcha_time']);
    return $ok;
}

function with_file_lock($lockFile, $callback) {
    $dir = dirname($lockFile);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $fp = fopen($lockFile, 'c');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    $result = false;
    try {
        $result = $callback();
    } catch (Exception $e) {
        log_write(date('Y-m-d H:i:s') . " Lock callback exception: " . $e->getMessage() . "\n");
    }
    flock($fp, LOCK_UN);
    fclose($fp);
    return $result;
}

function get_user_file($uid) {
    return USERS_DIR . '/' . intval($uid) . '.json';
}

function get_user_data($uid) {
    $file = get_user_file($uid);
    return json_read($file, null);
}

function get_user_profile($uid) {
    $data = get_user_data($uid);
    if (!$data) return null;
    return $data['profile'] ?? null;
}

function get_username_file($username) {
    $hash = md5(trim(strtolower($username)));
    return USERNAMES_DIR . '/' . $hash . '.json';
}

function get_username_uid($username) {
    $file = get_username_file($username);
    $data = json_read($file, null);
    return $data ? $data['uid'] : null;
}

function save_username_mapping($username, $uid) {
    if (!is_dir(USERNAMES_DIR)) @mkdir(USERNAMES_DIR, 0755, true);
    $file = get_username_file($username);
    return json_write($file, ['uid' => $uid, 'username' => strtolower(trim($username))]);
}

function delete_username_mapping($username) {
    $file = get_username_file($username);
    if (file_exists($file)) unlink($file);
}

function generate_mc_uuid($uid, $algorithm = 'offline', $username = null) {
    if ($algorithm === 'offline') {
        if ($username === null) {
            $username = '';
            $data = get_user_data($uid);
            if ($data && isset($data['profile']['username'])) {
                $username = $data['profile']['username'];
            }
        }
        $offlineHash = md5('OfflinePlayer:' . $username);
        $uuid = substr($offlineHash, 0, 8) . '-' . 
                substr($offlineHash, 8, 4) . '-' . 
                substr($offlineHash, 12, 4) . '-' . 
                substr($offlineHash, 16, 4) . '-' . 
                substr($offlineHash, 20, 12);
        return $uuid;
    } else {
        $hex = str_pad(dechex($uid), 8, '0', STR_PAD_LEFT);
        $uuid = substr($hex, 0, 8) . '-0000-4000-8000-' . str_pad(dechex(crc32((string)$uid)), 12, '0', STR_PAD_LEFT);
        return $uuid;
    }
}

function uuid_to_dashed($uuid) {
    $uuid = str_replace('-', '', $uuid);
    if (strlen($uuid) === 32) {
        return substr($uuid, 0, 8) . '-' . substr($uuid, 8, 4) . '-' . substr($uuid, 12, 4) . '-' . substr($uuid, 16, 4) . '-' . substr($uuid, 20, 12);
    }
    return $uuid;
}

function uuid_to_undashed($uuid) {
    return str_replace('-', '', $uuid);
}

function create_user($uid, $username, $password, $role = 'user') {
    $settings = json_read(DATA_DIR . '/settings.json', []);
    $algorithm = $settings['uuid_algorithm'] ?? 'offline';
    $uuid = generate_mc_uuid($uid, $algorithm, $username);

    $data = [
        'profile' => [
            'uid' => $uid,
            'uuid' => $uuid,
            'username' => $username,
            'password' => password_hash($password, PASSWORD_DEFAULT),
            'reg_time' => date('Y-m-d H:i:s'),
            'role' => $role
        ],
        'mc' => [
            'access_token' => '',
            'client_token' => '',
            'token_time' => 0,
            'server_id' => ''
        ],
        'skin' => [
            'url' => '',
            'model' => 'steve'
        ]
    ];
    return json_write(get_user_file($uid), $data);
}

function update_user_profile_field($uid, $field, $value) {
    $data = get_user_data($uid);
    if (!$data) return false;
    $data['profile'][$field] = $value;
    return json_write(get_user_file($uid), $data);
}

function update_user_data($uid, $data) {
    return json_write(get_user_file($uid), $data);
}

function remove_sensitive_fields(&$profile) {
    unset($profile['password']);
}

function is_mc_token_valid($data) {
    if (empty($data['mc']['access_token'])) return false;
    if (empty($data['mc']['token_time'])) return false;
    return (time() - $data['mc']['token_time']) < TOKEN_TTL;
}

function generate_yggdrasil_keys() {
    $config = [
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ];
    $res = openssl_pkey_new($config);
    if (!$res) {
        $res = openssl_pkey_new();
    }
    if (!$res) return null;
    openssl_pkey_export($res, $privateKey);
    $details = openssl_pkey_get_details($res);
    $publicKey = $details['key'];
    return [
        'private' => $privateKey,
        'public' => $publicKey,
        'created' => time(),
        'fingerprint' => md5($publicKey)
    ];
}

function get_or_create_yggdrasil_keys() {
    $keyFile = DATA_DIR . '/keys.json';
    $keys = json_read($keyFile, null);
    if ($keys && !empty($keys['private']) && !empty($keys['public'])) {
        return $keys;
    }
    $keys = generate_yggdrasil_keys();
    if (!$keys) return null;
    json_write($keyFile, $keys);
    return $keys;
}

function get_yggdrasil_public_key_pem() {
    $keys = get_or_create_yggdrasil_keys();
    return $keys ? $keys['public'] : '';
}

function sign_textures($textures_base64) {
    $keys = get_or_create_yggdrasil_keys();
    if (!$keys || empty($keys['private'])) return '';
    $signature = '';
    $ok = openssl_sign($textures_base64, $signature, $keys['private'], OPENSSL_ALGO_SHA256);
    return $ok ? base64_encode($signature) : '';
}

$action = $_GET['action'] ?? '';

$pathInfo = $_SERVER['PATH_INFO'] ?? $_SERVER['REQUEST_URI'] ?? '';
$pathInfo = str_replace($_SERVER['PHP_SELF'], '', $pathInfo);
$pathInfo = strtok($pathInfo, '?');

if (empty($action) && !empty($pathInfo)) {
    $pathParts = array_values(array_filter(explode('/', $pathInfo)));

    if (isset($pathParts[0]) && $pathParts[0] === 'authserver' && isset($pathParts[1])) {
        if ($pathParts[1] === 'authenticate' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = 'mc_authenticate';
        } elseif ($pathParts[1] === 'refresh' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = 'mc_refresh';
        } elseif ($pathParts[1] === 'validate' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = 'mc_validate';
        } elseif ($pathParts[1] === 'invalidate' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = 'mc_invalidate';
        } elseif ($pathParts[1] === 'signout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $action = 'mc_signout';
        }
    } elseif ($pathParts[0] === 'sessionserver' && isset($pathParts[1]) && $pathParts[1] === 'session' 
            && isset($pathParts[2]) && $pathParts[2] === 'minecraft' && isset($pathParts[3]) 
            && $pathParts[3] === 'profile' && isset($pathParts[4])) {
        $action = 'mc_session';
        $_GET['path'] = $pathParts[4];
    } elseif ($pathParts[0] === 'sessionserver' && isset($pathParts[1]) && $pathParts[1] === 'session'
            && isset($pathParts[2]) && $pathParts[2] === 'minecraft' && isset($pathParts[3])
            && $pathParts[3] === 'hasJoined') {
        $action = 'mc_has_joined';
    } elseif ($pathParts[0] === 'sessionserver' && isset($pathParts[1]) && $pathParts[1] === 'session'
            && isset($pathParts[2]) && $pathParts[2] === 'minecraft' && isset($pathParts[3])
            && $pathParts[3] === 'join') {
        $action = 'mc_join';
    } elseif ($pathParts[0] === 'api' && isset($pathParts[1]) && $pathParts[1] === 'user'
            && isset($pathParts[2]) && $pathParts[2] === 'profile' && isset($pathParts[3])) {
        if (isset($pathParts[4]) && $pathParts[4] === 'skin' && $_SERVER['REQUEST_METHOD'] === 'PUT') {
            $action = 'mc_upload_skin';
            $_GET['uuid'] = $pathParts[3];
        } elseif ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
            $action = 'mc_delete_skin';
            $_GET['uuid'] = $pathParts[3];
        }
    }
}

if (empty($action)) {
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    $isBrowser = strpos($accept, 'text/html') !== false && strpos($accept, 'application/json') === false;

    if ($isBrowser) {
        render_frontend();
        exit;
    }

    header('Content-Type: application/json');
    $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') 
        . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];

    $settings = json_read(DATA_DIR . '/settings.json', [
        'server_name' => 'SOT Auth Server'
    ]);

    $keys = get_or_create_yggdrasil_keys();
    $publicKey = $keys ? str_replace("\r\n", "\n", trim($keys['public'])) : '';

    $metadata = [
        'serverName' => $settings['server_name'] ?? 'SOT Auth Server',
        'implementationName' => 'SOT-Yggdrasil',
        'implementationVersion' => VERSION,
        'links' => [
            'homepage' => str_replace('index.php', '', $baseUrl),
            'register' => str_replace('index.php', '', $baseUrl)
        ],
        'feature' => [
            'no_email_login' => true,
            'enable_profile_key' => false
        ],
        'skinDomains' => [
            $_SERVER['HTTP_HOST']
        ],
        'signaturePublickey' => $publicKey,
        'api' => [
            'auth' => [
                'authenticate' => $baseUrl . '?action=mc_authenticate',
                'refresh' => $baseUrl . '?action=mc_refresh',
                'validate' => $baseUrl . '?action=mc_validate',
                'invalidate' => $baseUrl . '?action=mc_invalidate',
                'signout' => $baseUrl . '?action=mc_signout'
            ],
            'sessionserver' => [
                'session' => [
                    'minecraft' => [
                        'join' => $baseUrl . '?action=mc_join',
                        'hasJoined' => $baseUrl . '?action=mc_has_joined',
                        'profile' => [
                            'url' => $baseUrl . '?action=mc_session&path={uuid}',
                            'queryFields' => []
                        ]
                    ]
                ]
            ],
            'apiroot' => $baseUrl
        ]
    ];

    echo json_encode($metadata, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

switch ($action) {

    case 'getCsrfToken':
        success(['csrf_token' => ensure_csrf()]);
        break;

    case 'getCaptcha':
        success(['question' => generate_captcha()]);
        break;

    case 'getSettings':
        $settings = json_read(DATA_DIR . '/settings.json', [
            'server_name' => 'SOT Auth Server',
            'allow_register' => true,
            'uuid_algorithm' => 'offline'
        ]);
        success($settings);
        break;

    case 'register':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') error('请求方式错误');
        verify_csrf();

        $settings = json_read(DATA_DIR . '/settings.json', ['allow_register' => true]);
        if (empty($settings['allow_register'])) error('当前不允许注册');

        if (!empty($settings['register_time_start']) || !empty($settings['register_time_end'])) {
            if (!is_in_time_window($settings['register_time_start'] ?? '', $settings['register_time_end'] ?? '')) {
                error('当前不在注册时间窗口内，请稍后再试');
            }
        }

        $regRateLimit = intval($settings['register_rate_limit'] ?? 5);
        $regRateWindow = intval($settings['register_rate_window'] ?? 900);
        check_rate_limit('reg_' . get_client_ip(), $regRateLimit, $regRateWindow);

        if (!empty($settings['require_captcha_register'])) {
            $captchaAnswer = $_POST['captcha_answer'] ?? '';
            if (!verify_captcha($captchaAnswer)) {
                error('人机验证答案错误，请重新计算');
            }
        }

        $usernameInput = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        if (!preg_match('/^[a-zA-Z0-9_]{3,16}$/', $usernameInput)) {
            error('用户名仅限字母、数字、下划线，长度3-16位');
        }
        if (strlen($password) < 8 || !preg_match('/[A-Za-z]/', $password) || !preg_match('/[0-9]/', $password)) {
            error('密码至少8位，且必须同时包含字母和数字');
        }

        $result = with_file_lock(DATA_DIR . '/.register.lock', function() use ($usernameInput, $password) {
            if (get_username_uid($usernameInput)) {
                return ['error' => '注册信息有误，请更换用户名或稍后再试'];
            }
            $isFirst = count(glob(USERS_DIR . '/*.json')) === 0;
            $role = $isFirst ? 'admin' : 'user';
            $uid = generate_uid();
            if (!$uid) return ['error' => '系统繁忙，请稍后再试'];
            create_user($uid, $usernameInput, $password, $role);
            save_username_mapping($usernameInput, $uid);
            return ['uid' => $uid, 'username' => $usernameInput, 'role' => $role];
        });

        if (is_array($result) && isset($result['error'])) {
            error($result['error']);
        }
        if (!$result) error('系统繁忙，请稍后再试');

        session_regenerate_id(true);
        $_SESSION['uid'] = $result['uid'];
        $_SESSION['username'] = $result['username'];
        $_SESSION['role'] = $result['role'];
        ensure_csrf();

        success(['uid' => $result['uid'], 'username' => $result['username'], 'role' => $result['role']]);
        break;

    case 'login':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') error('请求方式错误');
        verify_csrf();

        $settings = json_read(DATA_DIR . '/settings.json', []);

        if (!empty($settings['login_time_start']) || !empty($settings['login_time_end'])) {
            if (!is_in_time_window($settings['login_time_start'] ?? '', $settings['login_time_end'] ?? '')) {
                error('当前不在登录时间窗口内，请稍后再试');
            }
        }

        $loginRateLimit = intval($settings['login_rate_limit'] ?? 5);
        $loginRateWindow = intval($settings['login_rate_window'] ?? 900);
        check_rate_limit('login_' . get_client_ip(), $loginRateLimit, $loginRateWindow);

        if (!empty($settings['require_captcha_login'])) {
            $captchaAnswer = $_POST['captcha_answer'] ?? '';
            if (!verify_captcha($captchaAnswer)) {
                error('人机验证答案错误，请重新计算');
            }
        }

        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';

        $uid = get_username_uid($username);
        if (!$uid) error('用户名或密码错误');

        $profile = get_user_profile($uid);
        if (!$profile || !password_verify($password, $profile['password'])) {
            error('用户名或密码错误');
        }

        session_regenerate_id(true);
        $_SESSION['uid'] = $uid;
        $_SESSION['username'] = $profile['username'];
        $_SESSION['role'] = $profile['role'];
        ensure_csrf();

        success([
            'uid' => $uid,
            'username' => $profile['username'],
            'role' => $profile['role']
        ]);
        break;

    case 'logout':
        verify_csrf();
        session_destroy();
        success();
        break;

    case 'getMe':
        if (empty($_SESSION['uid'])) {
            success(['logged_in' => false]);
            break;
        }
        $profile = get_user_profile($_SESSION['uid']);
        if (!$profile) {
            success(['logged_in' => false]);
            break;
        }
        remove_sensitive_fields($profile);
        success([
            'logged_in' => true,
            'uid' => $_SESSION['uid'],
            'username' => $profile['username'],
            'role' => $profile['role']
        ]);
        break;

    case 'adminUsers':
        require_admin();

        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            $users = [];
            $files = glob(USERS_DIR . '/*.json');
            foreach ($files as $f) {
                $uid = intval(basename($f, '.json'));
                $data = get_user_data($uid);
                if ($data) {
                    $profile = $data['profile'];
                    remove_sensitive_fields($profile);
                    $profile['skin_url'] = ($data['skin']['url'] ?? '') !== '';
                    $users[] = $profile;
                }
            }
            usort($users, function($a, $b) {
                return ($a['uid'] ?? 0) <=> ($b['uid'] ?? 0);
            });
            success(['users' => $users]);
        } else {
            verify_csrf();
            $targetUid = intval($_POST['uid'] ?? 0);
            $adminAction = $_POST['action'] ?? '';

            $targetProfile = get_user_profile($targetUid);
            if (!$targetProfile) error('用户不存在', 404);

            if ($adminAction === 'delete') {
                if ($targetUid == $_SESSION['uid']) error('不能删除当前登录账户');
                $allUsers = [];
                $files = glob(USERS_DIR . '/*.json');
                foreach ($files as $f) {
                    $u = get_user_profile(intval(basename($f, '.json')));
                    if ($u) $allUsers[] = $u;
                }
                $adminCount = count(array_filter($allUsers, function($u) { return ($u['role'] ?? '') === 'admin'; }));
                if ($targetProfile['role'] === 'admin' && $adminCount <= 1) {
                    error('不能删除最后一个管理员');
                }

                delete_username_mapping($targetProfile['username']);
                $userFile = get_user_file($targetUid);
                if (file_exists($userFile)) unlink($userFile);
                success();
            } elseif ($adminAction === 'setRole') {
                $newRole = $_POST['role'] ?? 'user';
                if (!in_array($newRole, ['admin', 'user'])) error('无效角色');
                update_user_profile_field($targetUid, 'role', $newRole);
                success();
            } elseif ($adminAction === 'resetPassword') {
                $newPass = $_POST['password'] ?? '';
                if (strlen($newPass) < 8 || !preg_match('/[A-Za-z]/', $newPass) || !preg_match('/[0-9]/', $newPass)) {
                    error('密码至少8位，且必须同时包含字母和数字');
                }
                update_user_profile_field($targetUid, 'password', password_hash($newPass, PASSWORD_DEFAULT));
                success();
            } else {
                error('未知操作');
            }
        }
        break;

    case 'adminMcSettings':
        require_admin();

        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            $settings = json_read(DATA_DIR . '/settings.json', [
                'server_name' => 'SOT Auth Server',
                'uuid_algorithm' => 'offline',
                'allow_register' => true
            ]);
            $keys = get_or_create_yggdrasil_keys();
            success([
                'settings' => [
                    'server_name' => $settings['server_name'] ?? 'SOT Auth Server',
                    'uuid_algorithm' => $settings['uuid_algorithm'] ?? 'offline',
                    'allow_register' => $settings['allow_register'] ?? true
                ],
                'public_key' => $keys['public'] ?? '',
                'fingerprint' => $keys['fingerprint'] ?? '',
                'key_created' => $keys['created'] ?? 0
            ]);
        } else {
            verify_csrf();
            $settings = json_read(DATA_DIR . '/settings.json', []);
            $oldAlgorithm = $settings['uuid_algorithm'] ?? 'offline';
            $newAlgorithm = $_POST['mc_uuid_algorithm'] ?? 'offline';

            if (!in_array($newAlgorithm, ['hash', 'offline'])) {
                error('UUID算法必须是hash或offline');
            }

            $settings['uuid_algorithm'] = $newAlgorithm;
            json_write(DATA_DIR . '/settings.json', $settings);

            if ($oldAlgorithm !== $newAlgorithm) {
                $userFiles = glob(USERS_DIR . '/*.json');
                foreach ($userFiles as $file) {
                    $data = json_read($file, null);
                    if ($data && isset($data['profile']['uid'])) {
                        $data['profile']['uuid'] = generate_mc_uuid($data['profile']['uid'], $newAlgorithm);
                        json_write($file, $data);
                    }
                }
            }

            success();
        }
        exit;

    case 'adminRegenKeys':
        require_admin();
        verify_csrf();
        $keys = generate_yggdrasil_keys();
        if (!$keys) error('密钥生成失败，请检查 OpenSSL 扩展');
        json_write(DATA_DIR . '/keys.json', $keys);
        success([
            'public_key' => $keys['public'],
            'fingerprint' => $keys['fingerprint'],
            'key_created' => $keys['created']
        ]);
        exit;

    case 'adminSettings':
        require_admin();
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') error('请求方式错误');
        verify_csrf();

        $settings = json_read(DATA_DIR . '/settings.json', []);

        $stringFields = ['server_name','site_logo','site_favicon','register_time_start','register_time_end','login_time_start','login_time_end'];
        foreach ($stringFields as $f) {
            if (isset($_POST[$f])) $settings[$f] = trim($_POST[$f]);
        }
        $intFields = ['register_rate_limit','register_rate_window','login_rate_limit','login_rate_window'];
        foreach ($intFields as $f) {
            if (isset($_POST[$f])) $settings[$f] = max(1, intval($_POST[$f]));
        }
        $boolFields = ['allow_register','require_captcha_register','require_captcha_login','trust_proxy'];
        foreach ($boolFields as $f) {
            if (isset($_POST[$f])) {
                $settings[$f] = $_POST[$f] === 'true' || $_POST[$f] === '1' || $_POST[$f] === 'on';
            }
        }

        json_write(DATA_DIR . '/settings.json', $settings);
        success($settings);
        break;

    case 'mc_authenticate':
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $mcUsername = trim($input['username'] ?? '');
        $mcPassword = $input['password'] ?? '';
        $clientToken = $input['clientToken'] ?? '';

        $uid = get_username_uid($mcUsername);
        if (!$uid) {
            http_response_code(401);
            echo json_encode(['error' => 'ForbiddenOperationException', 'errorMessage' => 'Invalid credentials']);
            exit;
        }

        $profile = get_user_profile($uid);
        if (!$profile || !password_verify($mcPassword, $profile['password'])) {
            http_response_code(401);
            echo json_encode(['error' => 'ForbiddenOperationException', 'errorMessage' => 'Invalid credentials']);
            exit;
        }

        $accessToken = bin2hex(random_bytes(16));
        if (empty($clientToken)) $clientToken = bin2hex(random_bytes(16));

        $data = get_user_data($uid);
        $data['mc']['access_token'] = $accessToken;
        $data['mc']['client_token'] = $clientToken;
        $data['mc']['token_time'] = time();
        $data['mc']['server_id'] = '';
        update_user_data($uid, $data);

        $uuidUndashed = uuid_to_undashed($profile['uuid']);
        $response = [
            'accessToken' => $accessToken,
            'clientToken' => $clientToken,
            'selectedProfile' => [
                'id' => $uuidUndashed,
                'name' => $profile['username']
            ],
            'availableProfiles' => [[
                'id' => $uuidUndashed,
                'name' => $profile['username']
            ]]
        ];
        echo json_encode($response);
        exit;

    case 'mc_refresh':
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $accessToken = $input['accessToken'] ?? '';
        $clientToken = $input['clientToken'] ?? '';

        $found = false;
        $userFiles = glob(USERS_DIR . '/*.json');
        foreach ($userFiles as $file) {
            $data = json_read($file, null);
            if ($data && !empty($data['mc']['access_token']) && 
                $data['mc']['access_token'] === $accessToken && 
                $data['mc']['client_token'] === $clientToken &&
                is_mc_token_valid($data)) {
                $found = true;
                $uid = $data['profile']['uid'];
                $profile = $data['profile'];
                break;
            }
        }

        if (!$found) {
            http_response_code(401);
            echo json_encode(['error' => 'ForbiddenOperationException', 'errorMessage' => 'Invalid token']);
            exit;
        }

        $newAccessToken = bin2hex(random_bytes(16));
        $data['mc']['access_token'] = $newAccessToken;
        $data['mc']['token_time'] = time();
        update_user_data($uid, $data);

        $uuidUndashed = uuid_to_undashed($profile['uuid']);
        $response = [
            'accessToken' => $newAccessToken,
            'clientToken' => $clientToken,
            'selectedProfile' => [
                'id' => $uuidUndashed,
                'name' => $profile['username']
            ]
        ];
        echo json_encode($response);
        exit;

    case 'mc_validate':
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $accessToken = $input['accessToken'] ?? '';
        $clientToken = $input['clientToken'] ?? '';

        $userFiles = glob(USERS_DIR . '/*.json');
        foreach ($userFiles as $file) {
            $data = json_read($file, null);
            if ($data && !empty($data['mc']['access_token']) && 
                $data['mc']['access_token'] === $accessToken &&
                (empty($clientToken) || $data['mc']['client_token'] === $clientToken) &&
                is_mc_token_valid($data)) {
                http_response_code(204);
                exit;
            }
        }

        http_response_code(401);
        echo json_encode(['error' => 'ForbiddenOperationException', 'errorMessage' => 'Invalid token']);
        exit;

    case 'mc_invalidate':
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $accessToken = $input['accessToken'] ?? '';
        $clientToken = $input['clientToken'] ?? '';

        $userFiles = glob(USERS_DIR . '/*.json');
        foreach ($userFiles as $file) {
            $data = json_read($file, null);
            if ($data && !empty($data['mc']['access_token']) && 
                $data['mc']['access_token'] === $accessToken &&
                (empty($clientToken) || $data['mc']['client_token'] === $clientToken)) {
                $data['mc']['access_token'] = '';
                $data['mc']['client_token'] = '';
                $data['mc']['token_time'] = 0;
                $data['mc']['server_id'] = '';
                update_user_data($data['profile']['uid'], $data);
                http_response_code(204);
                exit;
            }
        }

        http_response_code(204);
        exit;

    case 'mc_signout':
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $mcUsername = trim($input['username'] ?? '');
        $mcPassword = $input['password'] ?? '';

        $uid = get_username_uid($mcUsername);
        if (!$uid) {
            http_response_code(204);
            exit;
        }

        $profile = get_user_profile($uid);
        if ($profile && password_verify($mcPassword, $profile['password'])) {
            $data = get_user_data($uid);
            $data['mc']['access_token'] = '';
            $data['mc']['client_token'] = '';
            $data['mc']['token_time'] = 0;
            $data['mc']['server_id'] = '';
            update_user_data($uid, $data);
        }

        http_response_code(204);
        exit;

    case 'mc_session':
        $path = $_GET['path'] ?? '';
        $parts = explode('/', $path);
        $uuid = sanitize($parts[0] ?? '');

        if (empty($uuid)) {
            http_response_code(400);
            echo json_encode(['error' => 'IllegalArgumentException', 'errorMessage' => 'Missing UUID']);
            exit;
        }

        $uuidDashed = uuid_to_dashed($uuid);
        $uuidUndashed = uuid_to_undashed($uuid);

        $found = false;
        $userFiles = glob(USERS_DIR . '/*.json');
        foreach ($userFiles as $file) {
            $data = json_read($file, null);
            if ($data && ($data['profile']['uuid'] === $uuidDashed || 
                $data['profile']['uuid'] === $uuidUndashed || 
                uuid_to_undashed($data['profile']['uuid']) === $uuidUndashed)) {
                $found = true;
                $profile = $data['profile'];
                $skin = $data['skin'] ?? ['url' => '', 'model' => 'steve'];
                break;
            }
        }

        if (!$found) {
            http_response_code(204);
            exit;
        }

        $uuidUndashed = uuid_to_undashed($profile['uuid']);

        $properties = [];
        if (!empty($skin['url'])) {
            $textures = [
                'timestamp' => time() * 1000,
                'profileId' => $uuidUndashed,
                'profileName' => $profile['username'],
                'textures' => [
                    'SKIN' => [
                        'url' => $skin['url']
                    ]
                ]
            ];
            if (!empty($skin['model']) && $skin['model'] === 'alex') {
                $textures['textures']['SKIN']['metadata'] = ['model' => 'slim'];
            }
            $texturesValue = base64_encode(json_encode($textures));
            $prop = [
                'name' => 'textures',
                'value' => $texturesValue
            ];
            $signature = sign_textures($texturesValue);
            if ($signature) {
                $prop['signature'] = $signature;
            }
            $properties[] = $prop;
        }

        $response = [
            'id' => $uuidUndashed,
            'name' => $profile['username'],
            'properties' => $properties
        ];

        header('Content-Type: application/json');
        echo json_encode($response);
        exit;

    case 'mc_has_joined':
        header('Content-Type: application/json');
        $username = $_GET['username'] ?? '';
        $serverId = $_GET['serverId'] ?? '';

        if (empty($username) || empty($serverId)) {
            http_response_code(400);
            echo json_encode(['error' => 'IllegalArgumentException', 'errorMessage' => 'Missing parameters']);
            exit;
        }

        $uid = get_username_uid($username);
        if (!$uid) {
            http_response_code(204);
            exit;
        }

        $data = get_user_data($uid);
        if (!$data || !is_mc_token_valid($data) || empty($data['mc']['server_id']) || $data['mc']['server_id'] !== $serverId) {
            http_response_code(204);
            exit;
        }

        $profile = $data['profile'];
        $skin = $data['skin'] ?? ['url' => '', 'model' => 'steve'];
        $uuidUndashed = uuid_to_undashed($profile['uuid']);

        $properties = [];
        if (!empty($skin['url'])) {
            $textures = [
                'timestamp' => time() * 1000,
                'profileId' => $uuidUndashed,
                'profileName' => $profile['username'],
                'textures' => [
                    'SKIN' => [
                        'url' => $skin['url']
                    ]
                ]
            ];
            if (!empty($skin['model']) && $skin['model'] === 'alex') {
                $textures['textures']['SKIN']['metadata'] = ['model' => 'slim'];
            }
            $texturesValue = base64_encode(json_encode($textures));
            $prop = [
                'name' => 'textures',
                'value' => $texturesValue
            ];
            $signature = sign_textures($texturesValue);
            if ($signature) {
                $prop['signature'] = $signature;
            }
            $properties[] = $prop;
        }

        $response = [
            'id' => $uuidUndashed,
            'name' => $profile['username'],
            'properties' => $properties
        ];

        echo json_encode($response);
        exit;

    case 'mc_join':
        header('Content-Type: application/json');
        $input = json_decode(file_get_contents('php://input'), true);
        $accessToken = $input['accessToken'] ?? '';
        $selectedProfile = $input['selectedProfile'] ?? '';
        $serverId = $input['serverId'] ?? '';

        if (empty($accessToken) || empty($serverId) || empty($selectedProfile)) {
            http_response_code(400);
            echo json_encode(['error' => 'IllegalArgumentException', 'errorMessage' => 'Missing parameters']);
            exit;
        }

        $found = false;
        $userFiles = glob(USERS_DIR . '/*.json');
        foreach ($userFiles as $file) {
            $data = json_read($file, null);
            if ($data && !empty($data['mc']['access_token']) && 
                $data['mc']['access_token'] === $accessToken &&
                is_mc_token_valid($data)) {
                $profileUuid = uuid_to_undashed($data['profile']['uuid']);
                if ($profileUuid === uuid_to_undashed($selectedProfile)) {
                    $found = true;
                    $uid = $data['profile']['uid'];
                    break;
                }
            }
        }

        if (!$found) {
            http_response_code(401);
            echo json_encode(['error' => 'ForbiddenOperationException', 'errorMessage' => 'Invalid token']);
            exit;
        }

        $data['mc']['server_id'] = $serverId;
        update_user_data($uid, $data);

        http_response_code(204);
        exit;

    case 'mc_upload_skin':
        require_login();
        verify_csrf();
        $uid = get_current_uid();

        if (empty($_FILES['file'])) error('请选择皮肤文件');
        $file = $_FILES['file'];

        if ($file['error'] !== UPLOAD_ERR_OK) error('上传失败');
        if ($file['size'] > MAX_SKIN_SIZE) error('皮肤文件不能超过100KB');

        $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        if ($ext !== 'png') error('仅支持PNG格式');

        $imgInfo = getimagesize($file['tmp_name']);
        if (!$imgInfo || $imgInfo[0] !== 64 || !in_array($imgInfo[1], [32, 64])) {
            error('皮肤尺寸必须为64x32或64x64');
        }

        if (!is_dir(SKINS_DIR)) @mkdir(SKINS_DIR, 0755, true);

        $oldData = get_user_data($uid);
        if (!empty($oldData['skin']['url'])) {
            $oldFile = basename(parse_url($oldData['skin']['url'], PHP_URL_PATH));
            $oldPath = SKINS_DIR . '/' . sanitize($oldFile);
            if (is_file($oldPath)) unlink($oldPath);
        }

        $filename = $uid . '_' . time() . '.png';
        $filepath = SKINS_DIR . '/' . $filename;

        if (!move_uploaded_file($file['tmp_name'], $filepath)) error('保存失败');
        @chmod($filepath, 0644);

        $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') 
            . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
        $skinUrl = $baseUrl . '?action=mc_get_skin&file=' . urlencode($filename);

        $model = $_POST['model'] ?? 'steve';
        if (!in_array($model, ['steve', 'alex'])) $model = 'steve';

        $data = get_user_data($uid);
        $data['skin']['url'] = $skinUrl;
        $data['skin']['model'] = $model;
        update_user_data($uid, $data);

        success(['url' => $skinUrl]);
        exit;

    case 'mc_get_skin':
        $filename = sanitize($_GET['file'] ?? '');
        if (empty($filename)) error('缺少文件名', 404);

        $filepath = SKINS_DIR . '/' . $filename;
        if (!is_file($filepath)) error('皮肤文件不存在', 404);

        header('Content-Type: image/png');
        header('Content-Length: ' . filesize($filepath));
        header('Cache-Control: public, max-age=31536000, immutable');
        readfile($filepath);
        exit;

    case 'mc_delete_skin':
        require_login();
        verify_csrf();
        $uid = get_current_uid();

        $data = get_user_data($uid);
        if (!empty($data['skin']['url'])) {
            $oldFile = basename(parse_url($data['skin']['url'], PHP_URL_PATH));
            $oldPath = SKINS_DIR . '/' . sanitize($oldFile);
            if (is_file($oldPath)) unlink($oldPath);
        }
        $data['skin']['url'] = '';
        $data['skin']['model'] = 'steve';
        update_user_data($uid, $data);

        success();
        exit;

    case 'mc_info':
        require_login();
        $uid = get_current_uid();
        $data = get_user_data($uid);

        success([
            'uuid' => $data['profile']['uuid'],
            'username' => $data['profile']['username'],
            'skin' => $data['skin'] ?? ['url' => '', 'model' => 'steve']
        ]);
        exit;

    default:
        render_frontend();
        exit;
}


function render_frontend() {
    $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') 
        . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
    $apiUrl = $baseUrl;
    $csrfToken = ensure_csrf();

    $settings = json_read(DATA_DIR . '/settings.json', [
        'server_name' => 'SOT Auth Server',
        'allow_register' => true,
        'site_logo' => '',
        'site_favicon' => ''
    ]);

    $serverName = htmlspecialchars($settings['server_name'] ?? 'SOT Auth Server', ENT_QUOTES, 'UTF-8');
    $siteLogo = htmlspecialchars($settings['site_logo'] ?? '', ENT_QUOTES, 'UTF-8');
    $siteFavicon = htmlspecialchars($settings['site_favicon'] ?? '', ENT_QUOTES, 'UTF-8');

    $iconSun = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>';
    $iconMoon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    $iconUpload = '<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom:8px;opacity:0.7;"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>';
    $iconCheck = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    $iconClose = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';

    echo '<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">';
    if (!empty($siteFavicon)) {
        echo '<link rel="icon" type="image/png" href="' . $siteFavicon . '">';
    }
    echo '<title>' . $serverName . ' - 管理后台</title>
<style>
:root {
    --bg: #0b0b0f;
    --bg-secondary: #12121a;
    --card: #18181f;
    --card-hover: #20202a;
    --border: #2a2a35;
    --border-hover: #3a3a4a;
    --text: #e8e8f0;
    --text-secondary: #a0a0b0;
    --text-muted: #606070;
    --accent: #2ecc71;
    --accent-dark: #27ae60;
    --accent-glow: rgba(46,204,113,0.12);
    --danger: #e74c3c;
    --danger-hover: #c0392b;
    --warning: #f39c12;
    --info: #3498db;
    --radius: 14px;
    --radius-sm: 10px;
    --transition: all 0.2s cubic-bezier(0.4,0,0.2,1);
}

@media (prefers-color-scheme: light) {
    :root:not([data-theme]) {
        --bg: #f0f0f5;
        --bg-secondary: #ffffff;
        --card: #ffffff;
        --card-hover: #f5f5fa;
        --border: #e0e0e5;
        --border-hover: #d0d0d5;
        --text: #1a1a2e;
        --text-secondary: #6b6b7b;
        --text-muted: #9a9aaa;
        --accent-glow: rgba(46,204,113,0.10);
    }
}

html[data-theme="light"] {
    --bg: #f0f0f5;
    --bg-secondary: #ffffff;
    --card: #ffffff;
    --card-hover: #f5f5fa;
    --border: #e0e0e5;
    --border-hover: #d0d0d5;
    --text: #1a1a2e;
    --text-secondary: #6b6b7b;
    --text-muted: #9a9aaa;
    --accent-glow: rgba(46,204,113,0.10);
}

html[data-theme="dark"] {
    --bg: #0b0b0f;
    --bg-secondary: #12121a;
    --card: #18181f;
    --card-hover: #20202a;
    --border: #2a2a35;
    --border-hover: #3a3a4a;
    --text: #e8e8f0;
    --text-secondary: #a0a0b0;
    --text-muted: #606070;
    --accent-glow: rgba(46,204,113,0.12);
}

* { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color:transparent; }
html { -webkit-text-size-adjust:100%; }
body {
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height:100vh;
    line-height:1.6;
    -webkit-font-smoothing:antialiased;
    font-size:15px;
    transition: background 0.3s ease, color 0.3s ease;
}
.container { max-width:1200px; margin:0 auto; padding:16px; }
@media(min-width:640px){ .container{ padding:24px; } }
@media(min-width:1024px){ .container{ padding:32px; } }

.header {
    display:flex;
    flex-direction:column;
    gap:16px;
    margin-bottom:24px;
    padding-bottom:20px;
    border-bottom:1px solid var(--border);
}
@media(min-width:640px){
    .header{ flex-direction:row; justify-content:space-between; align-items:center; gap:24px; margin-bottom:32px; padding-bottom:24px; }
}
.header-brand { display:flex; align-items:center; gap:14px; }
.header-logo {
    width:44px; height:44px; min-width:44px;
    background: linear-gradient(135deg, var(--accent), var(--accent-dark));
    border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    font-size:22px; font-weight:800; color:#000; letter-spacing:-1px;
    overflow:hidden;
}
.header-logo img { width:100%; height:100%; object-fit:contain; }
.header-title h1 { font-size:20px; font-weight:700; letter-spacing:-0.02em; line-height:1.3; }
@media(min-width:640px){ .header-title h1{ font-size:24px; } }
.header-title p { color:var(--text-secondary); font-size:13px; margin-top:2px; }
.header-actions { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
.user-badge {
    display:flex; align-items:center; gap:8px;
    padding:8px 14px;
    background:var(--card);
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    font-size:13px;
}
.user-badge .role {
    padding:2px 8px;
    background:var(--accent);
    color:#000;
    border-radius:4px;
    font-size:11px;
    font-weight:700;
    text-transform:uppercase;
}
.nav {
    display:flex;
    gap:6px;
    margin-bottom:20px;
    padding:4px;
    background:var(--bg-secondary);
    border-radius:var(--radius);
    border:1px solid var(--border);
    overflow-x:auto;
    -webkit-overflow-scrolling:touch;
    scrollbar-width:none;
}
.nav::-webkit-scrollbar { display:none; }
.nav-btn {
    padding:10px 16px;
    border-radius:var(--radius-sm);
    border:none;
    background:transparent;
    color:var(--text-secondary);
    cursor:pointer;
    font-size:13px;
    font-weight:500;
    white-space:nowrap;
    transition:var(--transition);
    flex-shrink:0;
}
@media(min-width:640px){ .nav-btn{ padding:10px 20px; font-size:14px; } }
.nav-btn:hover { color:var(--text); background:var(--card); }
.nav-btn.active { color:var(--accent); background:var(--card); font-weight:600; }

.card {
    background:var(--card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:20px;
    margin-bottom:16px;
    transition: background 0.3s ease, border-color 0.3s ease;
}
@media(min-width:640px){ .card{ padding:24px; margin-bottom:20px; } }
.card-header {
    display:flex;
    justify-content:space-between;
    align-items:center;
    margin-bottom:18px;
    gap:12px;
    flex-wrap:wrap;
}
.card-header h3 {
    font-size:14px;
    font-weight:600;
    color:var(--accent);
    text-transform:uppercase;
    letter-spacing:0.08em;
}
.stats-grid {
    display:grid;
    grid-template-columns:repeat(2, 1fr);
    gap:12px;
    margin-bottom:20px;
}
@media(min-width:640px){ .stats-grid{ grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:16px; margin-bottom:24px; } }
.stat-card {
    background:var(--card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    padding:18px;
    transition: background 0.3s ease, border-color 0.3s ease;
}
.stat-value { font-size:28px; font-weight:700; color:var(--accent); line-height:1; margin-bottom:6px; }
@media(min-width:640px){ .stat-value{ font-size:32px; } }
.stat-label { font-size:12px; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.05em; }
.form-group { margin-bottom:18px; }
.form-group label {
    display:block;
    margin-bottom:6px;
    font-size:12px;
    font-weight:500;
    color:var(--text-secondary);
    text-transform:uppercase;
    letter-spacing:0.05em;
}
input, select, textarea {
    width:100%;
    padding:12px 14px;
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    background:var(--bg);
    color:var(--text);
    font-family:inherit;
    font-size:14px;
    outline:none;
    -webkit-appearance:none;
    appearance:none;
    transition:var(--transition);
}
input:focus, select:focus, textarea:focus {
    border-color:var(--accent);
    box-shadow:0 0 0 3px var(--accent-glow);
}
select { background-image:url("data:image/svg+xml,%3Csvg xmlns=\'http://www.w3.org/2000/svg\' width=\'12\' height=\'12\' viewBox=\'0 0 12 12\'%3E%3Cpath fill=\'%23a0a0b0\' d=\'M6 8L1 3h10z\'/%3E%3C/svg%3E"); background-repeat:no-repeat; background-position:right 14px center; padding-right:36px; }

.toggle-group { display:flex; align-items:center; gap:14px; cursor:pointer; user-select:none; }
.toggle-group .toggle-label { font-size:12px; font-weight:500; color:var(--text-secondary); text-transform:uppercase; letter-spacing:0.05em; flex:1; }
.toggle-switch {
    position:relative;
    width:52px; height:30px; min-width:52px;
    background:var(--border);
    border-radius:15px;
    transition:var(--transition);
    cursor:pointer;
}
.toggle-switch::after {
    content:"";
    position:absolute;
    top:3px; left:3px;
    width:24px; height:24px;
    background:var(--card);
    border-radius:50%;
    box-shadow:0 2px 6px rgba(0,0,0,0.25);
    transition:var(--transition);
}
.toggle-group input[type="checkbox"] {
    position:absolute;
    opacity:0;
    width:0; height:0;
}
.toggle-group input[type="checkbox"]:checked + .toggle-switch {
    background:var(--accent);
}
.toggle-group input[type="checkbox"]:checked + .toggle-switch::after {
    left:25px;
    background:#fff;
}
.toggle-group:active .toggle-switch::after { width:28px; }
.toggle-group input[type="checkbox"]:checked + .toggle-switch:active::after { left:21px; }

.btn {
    padding:12px 20px;
    border-radius:var(--radius-sm);
    border:none;
    background:var(--accent);
    color:#000;
    font-weight:600;
    cursor:pointer;
    font-size:14px;
    transition:var(--transition);
    display:inline-flex;
    align-items:center;
    justify-content:center;
    gap:8px;
    line-height:1.4;
}
.btn:hover { background:var(--accent-dark); transform:translateY(-1px); box-shadow:0 4px 14px var(--accent-glow); }
.btn-secondary { background:var(--border); color:var(--text); }
.btn-secondary:hover { background:var(--border-hover); box-shadow:none; transform:none; }
.btn-danger { background:var(--danger); color:#fff; }
.btn-danger:hover { background:var(--danger-hover); transform:translateY(-1px); }
.btn-sm { padding:7px 12px; font-size:12px; }
.btn-block { width:100%; }
.table-wrap { overflow-x:auto; -webkit-overflow-scrolling:touch; border-radius:var(--radius-sm); border:1px solid var(--border); }
table { width:100%; border-collapse:collapse; font-size:13px; }
th, td { padding:12px 14px; text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; }
@media(min-width:640px){ th,td{ padding:14px 16px; } }
th { color:var(--text-muted); font-weight:600; text-transform:uppercase; font-size:11px; background:var(--bg-secondary); }
tr:hover td { background:rgba(128,128,128,0.04); }
.badge {
    padding:4px 10px;
    border-radius:6px;
    font-size:11px;
    font-weight:700;
    text-transform:uppercase;
    display:inline-block;
}
.badge-admin { background:var(--accent); color:#000; }
.badge-user { background:var(--border); color:var(--text-secondary); }
.info-box {
    background:var(--bg-secondary);
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    padding:14px;
    font-family:ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    font-size:12px;
    word-break:break-all;
    line-height:1.5;
    color:var(--text-secondary);
}
.login-box { max-width:420px; margin:60px auto; }
@media(min-width:640px){ .login-box{ margin:100px auto; } }
.login-box .card-header { text-align:center; display:block; }
.login-tabs {
    display:flex;
    gap:8px;
    margin-bottom:20px;
}
.login-tab {
    flex:1;
    padding:12px;
    border-radius:var(--radius-sm);
    border:1px solid var(--border);
    background:transparent;
    color:var(--text-secondary);
    cursor:pointer;
    font-size:14px;
    font-weight:500;
    transition:var(--transition);
}
.login-tab.active { background:var(--accent); color:#000; border-color:var(--accent); }
.skin-preview {
    width:100%; max-width:200px; aspect-ratio:1;
    background:var(--bg-secondary);
    border:1px solid var(--border);
    border-radius:var(--radius-sm);
    display:flex; align-items:center; justify-content:center;
    margin:16px 0;
    overflow:hidden;
}
.skin-preview img { width:100%; height:100%; object-fit:contain; image-rendering:pixelated; }
.skin-preview-empty { color:var(--text-muted); font-size:13px; text-align:center; padding:20px; }
.upload-zone {
    border:2px dashed var(--border);
    border-radius:var(--radius);
    padding:32px 24px;
    text-align:center;
    cursor:pointer;
    margin-bottom:16px;
    transition:var(--transition);
}
@media(min-width:640px){ .upload-zone{ padding:40px; } }
.upload-zone:hover { border-color:var(--accent); background:var(--accent-glow); }
.toast-container {
    position:fixed;
    top:16px; right:16px;
    z-index:9999;
    display:flex;
    flex-direction:column;
    gap:8px;
    max-width:calc(100vw - 32px);
}
@media(min-width:640px){ .toast-container{ top:24px; right:24px; max-width:400px; } }
.toast {
    padding:14px 18px;
    border-radius:var(--radius-sm);
    background:var(--accent);
    color:#000;
    font-weight:600;
    font-size:14px;
    animation:slideIn 0.35s ease;
    box-shadow:0 8px 24px rgba(0,0,0,0.3);
    word-break:break-word;
}
.toast.error { background:var(--danger); color:#fff; }
@keyframes slideIn {
    from { transform:translateX(120px); opacity:0; }
    to { transform:translateX(0); opacity:1; }
}
.modal-overlay {
    position:fixed; inset:0;
    background:rgba(0,0,0,0.85);
    backdrop-filter:blur(10px);
    -webkit-backdrop-filter:blur(10px);
    z-index:1000;
    display:none; align-items:center; justify-content:center;
    padding:16px;
}
.modal-overlay.active { display:flex; }
.modal {
    background:var(--card);
    border:1px solid var(--border);
    border-radius:var(--radius);
    width:100%; max-width:460px;
    max-height:90vh;
    overflow-y:auto;
}
.modal-header {
    padding:18px 20px;
    border-bottom:1px solid var(--border);
    display:flex; justify-content:space-between; align-items:center;
    position:sticky; top:0; background:var(--card); z-index:1;
}
@media(min-width:640px){ .modal-header{ padding:20px 24px; } }
.modal-close {
    width:34px; height:34px;
    border-radius:50%;
    border:none;
    background:var(--border);
    color:var(--text);
    cursor:pointer;
    font-size:18px;
    display:flex; align-items:center; justify-content:center;
    transition:var(--transition);
}
.modal-close:hover { background:var(--danger); color:#fff; }
.modal-body { padding:20px; }
@media(min-width:640px){ .modal-body{ padding:24px; } }
.modal-footer {
    padding:16px 20px 20px;
    display:flex; gap:10px; justify-content:flex-end;
}
@media(min-width:640px){ .modal-footer{ padding:16px 24px 24px; } }
.empty-state { text-align:center; padding:48px 20px; color:var(--text-muted); font-size:14px; }
@media(min-width:640px){ .empty-state{ padding:60px 24px; } }
.loading { display:flex; justify-content:center; padding:40px; }
.spinner {
    width:32px; height:32px;
    border:2px solid var(--border);
    border-top-color:var(--accent);
    border-radius:50%;
    animation:spin 0.8s linear infinite;
}
@keyframes spin { to { transform:rotate(360deg); } }
.hidden { display:none !important; }
.w-full { width:100%; }
.text-sm { font-size:13px; }
.text-muted { color:var(--text-muted); }
.mt-2 { margin-top:8px; }
.mt-4 { margin-top:16px; }
.mb-4 { margin-bottom:16px; }
.gap-2 { gap:8px; }
.flex { display:flex; }
.flex-wrap { flex-wrap:wrap; }
.items-center { align-items:center; }
.justify-between { justify-content:space-between; }
.grid-2 { display:grid; grid-template-columns:repeat(2, 1fr); gap:12px; }
@media(min-width:640px){ .grid-2{ grid-template-columns:repeat(auto-fit, minmax(220px, 1fr)); } }
.section-title { font-size:18px; font-weight:700; margin-bottom:16px; letter-spacing:-0.01em; }
.captcha-question { color:var(--accent); font-weight:700; font-size:15px; }
.captcha-hint { font-size:12px; color:var(--text-muted); margin-top:4px; }
.status-dot {
    width:14px; height:14px; border-radius:50%; background:var(--accent); display:inline-block;
    box-shadow: 0 0 8px var(--accent);
}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-brand">
            <div class="header-logo">';
    if (!empty($siteLogo)) {
        echo '<img src="' . $siteLogo . '" alt="Logo">';
    } else {
        echo 'S';
    }
    echo '</div>
            <div class="header-title">
                <h1>' . $serverName . '</h1>
                <p>SOT身份验证服务器 v' . VERSION . '</p>
            </div>
        </div>
        <div class="header-actions" id="headerActions">
            <button class="btn btn-secondary btn-sm" id="themeToggle" onclick="toggleTheme()" title="切换主题">' . $iconSun . '</button>
            <div class="user-badge hidden" id="userBadge">
                <span id="userName"></span>
                <span class="role" id="userRole"></span>
            </div>
            <button class="btn btn-secondary hidden" id="logoutBtn" onclick="logout()">退出</button>
        </div>
    </div>

    <div id="loginSection">
        <div class="login-box card">
            <div class="card-header"><h3 style="font-size:18px; color:var(--text); text-transform:none; letter-spacing:0;">欢迎回来</h3></div>
            <div class="login-tabs">
                <button class="login-tab active" onclick="switchLoginTab(event, \'login\')">登录</button>
                <button class="login-tab" id="registerTabBtn" onclick="switchLoginTab(event, \'register\')">注册</button>
            </div>
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" id="loginUsername" placeholder="3-16位字母数字下划线" autocomplete="username" required>
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" id="loginPassword" placeholder="至少8位，含字母和数字" autocomplete="current-password" required>
                </div>
                <div class="form-group hidden" id="loginCaptchaGroup">
                    <label>人机验证 <span class="captcha-question" id="loginCaptchaQuestion"></span></label>
                    <input type="text" id="loginCaptchaAnswer" placeholder="输入计算结果" autocomplete="off">
                    <div class="captcha-hint">请通过人机验证以继续，确保您并非伪人</div>
                </div>
                <button type="submit" class="btn btn-block">登录</button>
            </form>
            <form id="registerForm" class="hidden" onsubmit="handleRegister(event)">
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" id="regUsername" placeholder="3-16位字母数字下划线" autocomplete="username" required>
                </div>
                <div class="form-group">
                    <label>密码</label>
                    <input type="password" id="regPassword" placeholder="至少8位，含字母和数字" autocomplete="new-password" required>
                </div>
                <div class="form-group hidden" id="regCaptchaGroup">
                    <label>人机验证 <span class="captcha-question" id="regCaptchaQuestion"></span></label>
                    <input type="text" id="regCaptchaAnswer" placeholder="输入计算结果" autocomplete="off">
                    <div class="captcha-hint">请通过人机验证以继续，确保您并非伪人</div>
                </div>
                <button type="submit" class="btn btn-block">注册</button>
            </form>
        </div>
    </div>

    <div id="adminSection" class="hidden">
        <div class="nav">
            <button class="nav-btn active" onclick="showTab(event, \'dashboard\')">仪表盘</button>
            <button class="nav-btn" onclick="showTab(event, \'users\')">用户管理</button>
            <button class="nav-btn" onclick="showTab(event, \'skin\')">我的皮肤</button>
            <button class="nav-btn" onclick="showTab(event, \'settings\')">系统设置</button>
            <button class="nav-btn" onclick="showTab(event, \'mcconfig\')">MC配置</button>
        </div>

        <div id="tab-dashboard" class="tab-content">
            <div class="stats-grid" id="adminStats">
                <div class="stat-card"><div class="stat-value" id="statTotalUsers">-</div><div class="stat-label">总用户</div></div>
                <div class="stat-card"><div class="stat-value" id="statAdminCount">-</div><div class="stat-label">管理员</div></div>
                <div class="stat-card"><div class="stat-value" id="statServerStatus"><span class="status-dot"></span></div><div class="stat-label">服务状态</div></div>
                <div class="stat-card"><div class="stat-value" id="statTokenTTL">24h</div><div class="stat-label">Token有效期</div></div>
            </div>
            <div class="card hidden" id="userInfoOnly">
                <div class="card-header"><h3>账户信息</h3></div>
                <div class="form-group">
                    <label>用户名</label>
                    <input type="text" id="myUsername" readonly>
                </div>
                <div class="form-group">
                    <label>UUID</label>
                    <div class="info-box" id="myUuid">加载中...</div>
                </div>
                <div class="form-group">
                    <label>角色</label>
                    <input type="text" id="myRole" readonly>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><h3>API 信息</h3></div>
                <div class="form-group">
                    <label>认证服务器地址</label>
                    <input type="text" id="apiRoot" readonly onclick="this.select()">
                </div>
                <div class="form-group hidden" id="adminApiDetail">
                    <label>公钥指纹</label>
                    <div class="info-box" id="publicKeyFp">加载中...</div>
                </div>
            </div>
        </div>

        <div id="tab-users" class="tab-content hidden">
            <div class="card">
                <div class="card-header"><h3>用户列表</h3></div>
                <div id="usersTable"><div class="loading"><div class="spinner"></div></div></div>
            </div>
        </div>

        <div id="tab-skin" class="tab-content hidden">
            <div class="card">
                <div class="card-header"><h3>当前皮肤</h3></div>
                <div id="skinPreviewArea"><div class="loading"><div class="spinner"></div></div></div>
            </div>
            <div class="card">
                <div class="card-header"><h3>上传新皮肤</h3></div>
                <div class="form-group">
                    <label>皮肤模型</label>
                    <select id="skinModel">
                        <option value="steve">Steve (标准 64x64)</option>
                        <option value="alex">Alex (纤细 64x64)</option>
                    </select>
                </div>
                <div class="upload-zone" onclick="document.getElementById(\'skinFile\').click()">
                    ' . $iconUpload . '
                    <div style="font-weight:500; margin-bottom:4px;">点击选择 PNG 皮肤文件</div>
                    <div class="text-sm text-muted">支持 64x32 或 64x64，最大 100KB</div>
                </div>
                <input type="file" id="skinFile" class="hidden" accept=".png" onchange="handleSkinSelect(event)">
                <div id="skinFileName" class="text-sm text-muted mb-4"></div>
                <button class="btn btn-block" onclick="uploadSkin()">上传皮肤</button>
            </div>
        </div>

        <div id="tab-settings" class="tab-content hidden">
            <div class="card">
                <div class="card-header"><h3>站点品牌</h3></div>
                <div class="form-group">
                    <label>服务器名称</label>
                    <input type="text" id="settingServerName">
                </div>
                <div class="form-group">
                    <label>站点 Logo URL（留空使用默认 S 图标）</label>
                    <input type="text" id="settingSiteLogo" placeholder="https://example.com/logo.png">
                </div>
                <div class="form-group">
                    <label>站点 Favicon URL（留空使用浏览器默认）</label>
                    <input type="text" id="settingSiteFavicon" placeholder="https://example.com/favicon.png">
                </div>
                <button class="btn" onclick="saveBrandSettings()">保存品牌设置</button>
            </div>

            <div class="card">
                <div class="card-header"><h3>注册限制</h3></div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>注册时间窗口 开始（HH:MM）</label>
                        <input type="time" id="settingRegTimeStart">
                    </div>
                    <div class="form-group">
                        <label>注册时间窗口 结束</label>
                        <input type="time" id="settingRegTimeEnd">
                    </div>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>注册频率限制（次）</label>
                        <input type="number" id="settingRegRateLimit" min="1" max="1000" placeholder="5">
                    </div>
                    <div class="form-group">
                        <label>频率限制窗口（秒）</label>
                        <input type="number" id="settingRegRateWindow" min="60" max="86400" placeholder="900">
                    </div>
                </div>
                <label class="toggle-group form-group" for="settingRequireCaptchaReg">
                    <span class="toggle-label">注册需要算术人机验证</span>
                    <input type="checkbox" id="settingRequireCaptchaReg">
                    <span class="toggle-switch"></span>
                </label>
                <button class="btn" onclick="saveRegisterSettings()">保存注册限制</button>
            </div>

            <div class="card">
                <div class="card-header"><h3>登录限制</h3></div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>登录时间窗口 开始（HH:MM）</label>
                        <input type="time" id="settingLoginTimeStart">
                    </div>
                    <div class="form-group">
                        <label>登录时间窗口 结束</label>
                        <input type="time" id="settingLoginTimeEnd">
                    </div>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>登录频率限制（次）</label>
                        <input type="number" id="settingLoginRateLimit" min="1" max="1000" placeholder="5">
                    </div>
                    <div class="form-group">
                        <label>频率限制窗口（秒）</label>
                        <input type="number" id="settingLoginRateWindow" min="60" max="86400" placeholder="900">
                    </div>
                </div>
                <label class="toggle-group form-group" for="settingRequireCaptchaLogin">
                    <span class="toggle-label">登录需要算术人机验证</span>
                    <input type="checkbox" id="settingRequireCaptchaLogin">
                    <span class="toggle-switch"></span>
                </label>
                <button class="btn" onclick="saveLoginSettings()">保存登录限制</button>
            </div>

            <div class="card">
                <div class="card-header"><h3>安全与网络</h3></div>
                <label class="toggle-group form-group" for="settingTrustProxy">
                    <span class="toggle-label">信任反向代理（开启后读取 X-Forwarded-For 获取真实 IP，仅在已知可信代理环境下开启，否则易被伪造）</span>
                    <input type="checkbox" id="settingTrustProxy">
                    <span class="toggle-switch"></span>
                </label>
                <label class="toggle-group form-group" for="settingAllowRegister">
                    <span class="toggle-label">允许新用户注册</span>
                    <input type="checkbox" id="settingAllowRegister">
                    <span class="toggle-switch"></span>
                </label>
                <button class="btn" onclick="saveSecuritySettings()">保存安全设置</button>
            </div>
        </div>

        <div id="tab-mcconfig" class="tab-content hidden">
            <div class="card">
                <div class="card-header"><h3>UUID 生成算法</h3></div>
                <div class="form-group">
                    <label>当前算法</label>
                    <select id="mcUuidAlgorithm">
                        <option value="offline">Offline</option>
                        <option value="hash">Hash</option>
                    </select>
                    <div class="text-sm text-muted mt-2">
                        Offline: 使用离线算法，保留兼容性<br>
                        Hash: 基于用户 ID 生成，更稳定可靠<br><br>
                        <strong style="color:var(--danger);">警告：切换算法将重新生成所有用户 UUID！</strong>
                    </div>
                </div>
                <button class="btn" onclick="saveMcSettings()">保存 MC 配置</button>
            </div>
            <div class="card">
                <div class="card-header" style="flex-wrap:wrap; gap:12px;">
                    <h3>签名密钥管理</h3>
                    <button class="btn btn-sm btn-danger" onclick="regenKeys()">重新生成密钥对</button>
                </div>
                <div class="form-group">
                    <label>当前公钥</label>
                    <div class="info-box" id="mcPublicKey" style="max-height:200px; overflow-y:auto;">加载中...</div>
                </div>
                <div class="form-group">
                    <label>密钥指纹</label>
                    <div class="info-box" id="mcKeyFingerprint">加载中...</div>
                </div>
                <div class="text-sm text-muted mt-2" style="color:var(--warning);">
                    重新生成密钥后，所有现有皮肤签名将失效，用户需要重新上传皮肤。
                </div>
            </div>
        </div>
    </div>
</div>

<div class="toast-container" id="toastContainer"></div>

<div class="modal-overlay" id="deleteModal">
    <div class="modal">
        <div class="modal-header"><h3>确认删除</h3><button class="modal-close" onclick="closeDeleteModal()">' . $iconClose . '</button></div>
        <div class="modal-body"><p id="deleteMessage">确定要删除该用户吗？此操作不可撤销。</p></div>
        <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeDeleteModal()">取消</button>
            <button class="btn btn-danger" id="confirmDeleteBtn">确认删除</button>
        </div>
    </div>
</div>

<div class="modal-overlay" id="roleModal">
    <div class="modal">
        <div class="modal-header"><h3>修改角色</h3><button class="modal-close" onclick="closeRoleModal()">' . $iconClose . '</button></div>
        <div class="modal-body">
            <p class="mb-4" id="roleMessage">选择新角色：</p>
            <div class="grid-2">
                <button class="btn btn-secondary" onclick="confirmRoleChange(\'admin\')">管理员</button>
                <button class="btn btn-secondary" onclick="confirmRoleChange(\'user\')">普通用户</button>
            </div>
        </div>
    </div>
</div>

<script>
const API = "' . $apiUrl . '?action=";
let CSRF_TOKEN = "' . $csrfToken . '";
let currentUser = null;
let deleteCallback = null;
let roleChangeCallback = null;
let selectedSkinFile = null;

const ICON_SUN = \'' . str_replace("'", "\\'", $iconSun) . '\';
const ICON_MOON = \'' . str_replace("'", "\\'", $iconMoon) . '\';

document.addEventListener("DOMContentLoaded", function() {
    initTheme();
    refreshCsrfToken().then(function() {
        checkLogin();
    });
    document.getElementById("apiRoot").value = location.protocol + "//" + location.host + location.pathname;
});

function initTheme() {
    var saved = localStorage.getItem("theme");
    var prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
    var theme = saved || (prefersDark ? "dark" : "light");
    document.documentElement.setAttribute("data-theme", theme);
    updateThemeIcon(theme);
}

function toggleTheme() {
    var current = document.documentElement.getAttribute("data-theme") || "dark";
    var next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    updateThemeIcon(next);
}

function updateThemeIcon(theme) {
    var btn = document.getElementById("themeToggle");
    if (btn) btn.innerHTML = theme === "dark" ? ICON_SUN : ICON_MOON;
}

async function refreshCsrfToken() {
    try {
        var res = await fetch(API + "getCsrfToken", { credentials: "same-origin" });
        var data = await res.json();
        if (data.success && data.csrf_token) {
            CSRF_TOKEN = data.csrf_token;
        }
    } catch (e) {
        console.error("Failed to refresh CSRF token", e);
    }
}

async function apiCall(action, params, method) {
    params = params || {};
    method = method || "GET";
    var url = API + action;
    var opts = { method: method, credentials: "same-origin" };
    var fullUrl = url;
    if (method === "POST") {
        if (params instanceof FormData) {
            params.append("csrf_token", CSRF_TOKEN);
            opts.body = params;
        } else {
            params["csrf_token"] = CSRF_TOKEN;
            opts.headers = { "Content-Type": "application/x-www-form-urlencoded" };
            opts.body = new URLSearchParams(params).toString();
        }
    } else if (Object.keys(params).length > 0) {
        fullUrl += "&" + new URLSearchParams(params).toString();
    }
    try {
        var res = await fetch(fullUrl, opts);
        if (res.status === 204) return { success: true };
        var data = await res.json();
        if (!data.success && data.message && data.message.indexOf("安全验证失败") !== -1) {
            await refreshCsrfToken();
            if (method === "POST") {
                if (params instanceof FormData) {
                    var newForm = new FormData();
                    for (var pair of params.entries()) {
                        if (pair[0] !== "csrf_token") {
                            newForm.append(pair[0], pair[1]);
                        }
                    }
                    newForm.append("csrf_token", CSRF_TOKEN);
                    opts.body = newForm;
                } else {
                    params["csrf_token"] = CSRF_TOKEN;
                    opts.body = new URLSearchParams(params).toString();
                }
            }
            res = await fetch(fullUrl, opts);
            if (res.status === 204) return { success: true };
            data = await res.json();
        }
        return data;
    } catch (err) {
        showToast("网络错误: " + err.message, "error");
        throw err;
    }
}

async function checkLogin() {
    var data = await apiCall("getMe");
    if (data.success && data.logged_in) {
        currentUser = data;
        showAdmin();
    } else {
        showLogin();
    }
}

async function showLogin() {
    document.getElementById("loginSection").classList.remove("hidden");
    document.getElementById("adminSection").classList.add("hidden");
    document.getElementById("userBadge").classList.add("hidden");
    document.getElementById("logoutBtn").classList.add("hidden");

    var s = await apiCall("getSettings");
    if (s.success) {
        var regTab = document.getElementById("registerTabBtn");
        if (s.allow_register === false) {
            regTab.classList.add("hidden");
        } else {
            regTab.classList.remove("hidden");
        }

        var loginCap = document.getElementById("loginCaptchaGroup");
        var regCap = document.getElementById("regCaptchaGroup");
        if (s.require_captcha_login) {
            loginCap.classList.remove("hidden");
            loadCaptcha("login");
        } else {
            loginCap.classList.add("hidden");
        }
        if (s.require_captcha_register) {
            regCap.classList.remove("hidden");
            loadCaptcha("register");
        } else {
            regCap.classList.add("hidden");
        }
    }
}

function showAdmin() {
    document.getElementById("loginSection").classList.add("hidden");
    document.getElementById("adminSection").classList.remove("hidden");
    document.getElementById("userBadge").classList.remove("hidden");
    document.getElementById("logoutBtn").classList.remove("hidden");
    document.getElementById("userName").textContent = currentUser.username;
    document.getElementById("userRole").textContent = (currentUser.role === "admin" ? "管理员" : "用户");

    var isAdmin = currentUser.role === "admin";
    var navButtons = document.querySelectorAll(".nav-btn");
    navButtons[0].textContent = isAdmin ? "仪表盘" : "我的信息";
    navButtons[1].style.display = isAdmin ? "" : "none";
    navButtons[2].style.display = "";
    navButtons[3].style.display = isAdmin ? "" : "none";
    navButtons[4].style.display = isAdmin ? "" : "none";

    if (isAdmin) {
        document.getElementById("adminStats").classList.remove("hidden");
        document.getElementById("adminApiDetail").classList.remove("hidden");
        document.getElementById("userInfoOnly").classList.add("hidden");
    } else {
        document.getElementById("adminStats").classList.add("hidden");
        document.getElementById("adminApiDetail").classList.add("hidden");
        document.getElementById("userInfoOnly").classList.remove("hidden");
    }

    loadDashboard();
}

function switchLoginTab(e, tab) {
    document.querySelectorAll(".login-tab").forEach(function(t) { t.classList.remove("active"); });
    e.target.classList.add("active");
    if (tab === "login") {
        document.getElementById("loginForm").classList.remove("hidden");
        document.getElementById("registerForm").classList.add("hidden");
    } else {
        document.getElementById("loginForm").classList.add("hidden");
        document.getElementById("registerForm").classList.remove("hidden");
    }
}

async function loadCaptcha(type) {
    var data = await apiCall("getCaptcha");
    if (data.success && data.question) {
        var questionEl = document.getElementById(type + "CaptchaQuestion");
        var inputEl = document.getElementById(type + "CaptchaAnswer");
        if (questionEl) questionEl.textContent = data.question;
        if (inputEl) inputEl.value = "";
    }
}

async function handleLogin(e) {
    e.preventDefault();
    var username = document.getElementById("loginUsername").value.trim();
    var password = document.getElementById("loginPassword").value;
    if (!username || !password) return;
    var params = { username: username, password: password };
    var capGroup = document.getElementById("loginCaptchaGroup");
    if (!capGroup.classList.contains("hidden")) {
        params.captcha_answer = document.getElementById("loginCaptchaAnswer").value;
    }
    var data = await apiCall("login", params, "POST");
    if (data.success) {
        currentUser = data;
        showToast("登录成功");
        showAdmin();
    } else {
        showToast(data.message || "登录失败", "error");
        if (!capGroup.classList.contains("hidden")) loadCaptcha("login");
    }
}

async function handleRegister(e) {
    e.preventDefault();
    var username = document.getElementById("regUsername").value.trim();
    var password = document.getElementById("regPassword").value;
    if (!username || !password) return;
    var params = { username: username, password: password };
    var capGroup = document.getElementById("regCaptchaGroup");
    if (!capGroup.classList.contains("hidden")) {
        params.captcha_answer = document.getElementById("regCaptchaAnswer").value;
    }
    var data = await apiCall("register", params, "POST");
    if (data.success) {
        currentUser = data;
        showToast("注册成功");
        showAdmin();
    } else {
        showToast(data.message || "注册失败", "error");
        if (!capGroup.classList.contains("hidden")) loadCaptcha("register");
    }
}

async function logout() {
    await apiCall("logout", {}, "POST");
    currentUser = null;
    showToast("已退出登录");
    location.reload();
}

function showTab(e, tab) {
    document.querySelectorAll(".nav-btn").forEach(function(btn) { btn.classList.remove("active"); });
    e.target.classList.add("active");
    document.querySelectorAll(".tab-content").forEach(function(c) { c.classList.add("hidden"); });
    document.getElementById("tab-" + tab).classList.remove("hidden");
    if (tab === "dashboard") loadDashboard();
    if (tab === "users") loadUsers();
    if (tab === "skin") loadSkin();
    if (tab === "settings") loadSettings();
    if (tab === "mcconfig") loadMcConfig();
}

async function loadDashboard() {
    var isAdmin = currentUser.role === "admin";
    document.getElementById("apiRoot").value = location.protocol + "//" + location.host + location.pathname;

    if (isAdmin) {
        var usersData = await apiCall("adminUsers");
        if (usersData.success) {
            document.getElementById("statTotalUsers").textContent = usersData.users.length;
            var adminCount = usersData.users.filter(function(u) { return u.role === "admin"; }).length;
            document.getElementById("statAdminCount").textContent = adminCount;
        }
        var mcData = await apiCall("adminMcSettings");
        if (mcData.success) {
            document.getElementById("publicKeyFp").textContent = mcData.fingerprint ? "MD5: " + mcData.fingerprint : "未配置";
        }
    } else {
        var data = await apiCall("mc_info");
        if (data.success) {
            document.getElementById("myUuid").textContent = data.uuid;
            document.getElementById("myUsername").value = data.username;
            document.getElementById("myRole").value = "普通用户";
        }
    }
}

async function loadUsers() {
    var data = await apiCall("adminUsers");
    var container = document.getElementById("usersTable");
    if (!data.success || !data.users.length) {
        container.innerHTML = "<div class=\"empty-state\">暂无用户</div>";
        return;
    }
    var iconCheck = \'' . str_replace("'", "\\'", $iconCheck) . '\';
    var html = "<div class=\"table-wrap\"><table><thead><tr><th>UID</th><th>用户名</th><th>角色</th><th>注册时间</th><th>皮肤</th><th>操作</th></tr></thead><tbody>";
    data.users.forEach(function(u) {
        var roleClass = u.role === "admin" ? "badge-admin" : "badge-user";
        var roleText = u.role === "admin" ? "管理员" : "用户";
        html += "<tr>" +
            "<td>" + u.uid + "</td>" +
            "<td>" + escapeHtml(u.username) + "</td>" +
            "<td><span class=\"badge " + roleClass + "\">" + roleText + "</span></td>" +
            "<td>" + (u.reg_time || "") + "</td>" +
            "<td>" + (u.skin_url ? iconCheck : "-") + "</td>" +
            "<td>" +
                "<button class=\"btn btn-sm btn-secondary\" onclick=\"openRoleModal(" + u.uid + ", \'" + u.role + "\', \'" + escapeHtml(u.username) + "\')\">改角色</button> " +
                "<button class=\"btn btn-sm btn-danger\" onclick=\"confirmDeleteUser(" + u.uid + ", \'" + escapeHtml(u.username) + "\')\">删除</button>" +
            "</td>" +
        "</tr>";
    });
    html += "</tbody></table></div>";
    container.innerHTML = html;
}

function openRoleModal(uid, currentRole, username) {
    roleChangeCallback = function(newRole) {
        apiCall("adminUsers", { uid: uid, action: "setRole", role: newRole }, "POST").then(function(data) {
            if (data.success) {
                showToast("角色已更新");
                closeRoleModal();
                loadUsers();
                loadDashboard();
            } else {
                showToast(data.message || "操作失败", "error");
            }
        });
    };
    document.getElementById("roleMessage").textContent = "修改用户 " + username + " (UID: " + uid + ") 的角色：";
    document.getElementById("roleModal").classList.add("active");
}

function confirmRoleChange(role) {
    if (roleChangeCallback) roleChangeCallback(role);
}

function closeRoleModal() {
    document.getElementById("roleModal").classList.remove("active");
    roleChangeCallback = null;
}

function confirmDeleteUser(uid, username) {
    deleteCallback = function() {
        apiCall("adminUsers", { uid: uid, action: "delete" }, "POST").then(function(data) {
            if (data.success) {
                showToast("删除成功");
                closeDeleteModal();
                loadUsers();
                loadDashboard();
            } else {
                showToast(data.message || "删除失败", "error");
            }
        });
    };
    document.getElementById("deleteMessage").textContent = "确定要删除用户 \"" + username + "\" (UID: " + uid + ") 吗？此操作不可撤销。";
    document.getElementById("confirmDeleteBtn").onclick = deleteCallback;
    document.getElementById("deleteModal").classList.add("active");
}

function closeDeleteModal() {
    document.getElementById("deleteModal").classList.remove("active");
    deleteCallback = null;
}

async function loadSkin() {
    var data = await apiCall("mc_info");
    var container = document.getElementById("skinPreviewArea");
    if (!data.success) { container.innerHTML = "<div class=\"empty-state\">加载失败</div>"; return; }
    var skin = data.skin || { url: "", model: "steve" };
    var html = "<div class=\"info-box\">UUID: " + data.uuid + "<br>用户名: " + escapeHtml(data.username) + "<br>模型: " + (skin.model === "alex" ? "Alex (纤细)" : "Steve (标准)") + "</div>";
    if (skin.url) {
        html += "<div class=\"skin-preview\"><img src=\"" + skin.url + "\" alt=\"当前皮肤\" onerror=\"this.parentElement.innerHTML=\'<div class=skin-preview-empty>图片加载失败</div>\'\"></div>";
        html += "<button class=\"btn btn-danger btn-block\" onclick=\"deleteSkin()\">删除皮肤</button>";
    } else {
        html += "<div class=\"skin-preview skin-preview-empty\">暂无皮肤</div>";
    }
    container.innerHTML = html;
}

async function deleteSkin() {
    if (!confirm("确定要删除当前皮肤吗？")) return;
    var data = await apiCall("mc_delete_skin", {}, "POST");
    if (data.success) { showToast("皮肤已删除"); loadSkin(); }
    else showToast(data.message || "删除失败", "error");
}

function handleSkinSelect(e) {
    var file = e.target.files[0];
    if (!file) return;
    selectedSkinFile = file;
    document.getElementById("skinFileName").textContent = "已选择: " + file.name + " (" + (file.size / 1024).toFixed(1) + " KB)";
}

async function uploadSkin() {
    if (!selectedSkinFile) { showToast("请选择皮肤文件", "error"); return; }
    var formData = new FormData();
    formData.append("file", selectedSkinFile);
    formData.append("model", document.getElementById("skinModel").value);
    try {
        var data = await apiCall("mc_upload_skin", formData, "POST");
        if (data.success) {
            showToast("皮肤上传成功");
            selectedSkinFile = null;
            document.getElementById("skinFileName").textContent = "";
            document.getElementById("skinFile").value = "";
            loadSkin();
        } else showToast(data.message || "上传失败", "error");
    } catch (err) { showToast("网络错误", "error"); }
}

async function loadSettings() {
    var data = await apiCall("getSettings");
    if (data.success) {
        document.getElementById("settingServerName").value = data.server_name || "";
        document.getElementById("settingSiteLogo").value = data.site_logo || "";
        document.getElementById("settingSiteFavicon").value = data.site_favicon || "";
        document.getElementById("settingRegTimeStart").value = data.register_time_start || "";
        document.getElementById("settingRegTimeEnd").value = data.register_time_end || "";
        document.getElementById("settingRegRateLimit").value = data.register_rate_limit || 5;
        document.getElementById("settingRegRateWindow").value = data.register_rate_window || 900;
        document.getElementById("settingLoginTimeStart").value = data.login_time_start || "";
        document.getElementById("settingLoginTimeEnd").value = data.login_time_end || "";
        document.getElementById("settingLoginRateLimit").value = data.login_rate_limit || 5;
        document.getElementById("settingLoginRateWindow").value = data.login_rate_window || 900;
        document.getElementById("settingRequireCaptchaReg").checked = !!data.require_captcha_register;
        document.getElementById("settingRequireCaptchaLogin").checked = !!data.require_captcha_login;
        document.getElementById("settingTrustProxy").checked = !!data.trust_proxy;
        document.getElementById("settingAllowRegister").checked = data.allow_register !== false;
    }
}

async function saveBrandSettings() {
    var data = await apiCall("adminSettings", {
        server_name: document.getElementById("settingServerName").value,
        site_logo: document.getElementById("settingSiteLogo").value,
        site_favicon: document.getElementById("settingSiteFavicon").value
    }, "POST");
    if (data.success) {
        showToast("品牌设置已保存");
        document.querySelector(".header-title h1").textContent = document.getElementById("settingServerName").value || "SOT Auth Server";
    } else showToast(data.message || "保存失败", "error");
}

async function saveRegisterSettings() {
    var data = await apiCall("adminSettings", {
        register_time_start: document.getElementById("settingRegTimeStart").value,
        register_time_end: document.getElementById("settingRegTimeEnd").value,
        register_rate_limit: document.getElementById("settingRegRateLimit").value,
        register_rate_window: document.getElementById("settingRegRateWindow").value,
        require_captcha_register: document.getElementById("settingRequireCaptchaReg").checked ? "true" : "false"
    }, "POST");
    if (data.success) showToast("注册限制已保存");
    else showToast(data.message || "保存失败", "error");
}

async function saveLoginSettings() {
    var data = await apiCall("adminSettings", {
        login_time_start: document.getElementById("settingLoginTimeStart").value,
        login_time_end: document.getElementById("settingLoginTimeEnd").value,
        login_rate_limit: document.getElementById("settingLoginRateLimit").value,
        login_rate_window: document.getElementById("settingLoginRateWindow").value,
        require_captcha_login: document.getElementById("settingRequireCaptchaLogin").checked ? "true" : "false"
    }, "POST");
    if (data.success) showToast("登录限制已保存");
    else showToast(data.message || "保存失败", "error");
}

async function saveSecuritySettings() {
    var data = await apiCall("adminSettings", {
        trust_proxy: document.getElementById("settingTrustProxy").checked ? "true" : "false",
        allow_register: document.getElementById("settingAllowRegister").checked ? "true" : "false"
    }, "POST");
    if (data.success) showToast("安全设置已保存");
    else showToast(data.message || "保存失败", "error");
}

async function loadMcConfig() {
    var data = await apiCall("adminMcSettings");
    if (data.success && data.settings) {
        document.getElementById("mcUuidAlgorithm").value = data.settings.uuid_algorithm || "offline";
        document.getElementById("mcPublicKey").textContent = data.public_key || "未配置";
        document.getElementById("mcKeyFingerprint").textContent = data.fingerprint ? "MD5: " + data.fingerprint : "未配置";
    }
}

async function saveMcSettings() {
    var newAlgorithm = document.getElementById("mcUuidAlgorithm").value;
    if (!confirm("切换 UUID 算法将重新生成所有用户的 UUID，确定继续吗？")) return;
    var data = await apiCall("adminMcSettings", { mc_uuid_algorithm: newAlgorithm }, "POST");
    if (data.success) showToast("MC配置已保存");
    else showToast(data.message || "保存失败", "error");
}

async function regenKeys() {
    if (!confirm("重新生成密钥将使所有现有皮肤签名失效，用户需要重新上传皮肤。确定继续吗？")) return;
    var data = await apiCall("adminRegenKeys", {}, "POST");
    if (data.success) {
        showToast("密钥已重新生成");
        document.getElementById("mcPublicKey").textContent = data.public_key || "";
        document.getElementById("mcKeyFingerprint").textContent = data.fingerprint ? "MD5: " + data.fingerprint : "未配置";
    } else {
        showToast(data.message || "密钥生成失败", "error");
    }
}

function showToast(message, type) {
    type = type || "success";
    var container = document.getElementById("toastContainer");
    var toast = document.createElement("div");
    toast.className = "toast " + (type === "error" ? "error" : "");
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(function() {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(120px)";
        setTimeout(function() { toast.remove(); }, 350);
    }, 3000);
}

function escapeHtml(text) {
    var div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
}
</script>
</body>
</html>';
}

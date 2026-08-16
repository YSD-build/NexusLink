<?php
/**
 * NexusLink 开放 API v1 PHP 客户端
 * 零第三方依赖（php-curl 扩展），支持客户端/隧道/流量/API Key 管理。
 *
 * 使用：
 *   $api = new NexusLinkClient('http://SERVER:7001', 'dev_api_key_789');
 *   $api->createClient('customer-a', 'tok_a_1', 3, 0);
 *   $api->createProxy('web', 'tcp', 8099, 9000, '127.0.0.1', 'customer-a');
 *   print_r($api->getTraffic('customer-a'));
 */

class NexusLinkClient
{
    /** @var string */
    private $baseURL;
    /** @var string */
    private $apiKey;
    /** @var float 超时（秒） */
    private $timeout;

    public function __construct($baseURL, $apiKey, $timeout = 15.0)
    {
        $this->baseURL = rtrim($baseURL, '/');
        $this->apiKey  = $apiKey;
        $this->timeout = $timeout;
    }

    /**
     * 发送请求
     * @param string $method GET/POST/DELETE
     * @param string $path
     * @param array|null $body
     * @return array
     * @throws Exception
     */
    private function request($method, $path, $body = null)
    {
        $ch = curl_init($this->baseURL . $path);
        $headers = ['X-API-Key: ' . $this->apiKey, 'Content-Type: application/json'];
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_CUSTOMREQUEST  => $method,
        ];
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = json_encode($body, JSON_UNESCAPED_UNICODE);
        }
        curl_setopt_array($ch, $opts);
        $raw   = curl_exec($ch);
        $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error !== '') {
            throw new Exception('curl error: ' . $error);
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $data = ['success' => false, 'error' => 'invalid response'];
        }
        if ($code < 200 || $code >= 300 || (isset($data['success']) && $data['success'] === false)) {
            throw new Exception('API ' . $code . ': ' . (isset($data['error']) ? $data['error'] : 'error'));
        }
        return $data;
    }

    // ==================== 客户端管理 ====================
    public function createClient($name, $token, $maxTunnels = 0, $maxTrafficBytes = 0)
    {
        return $this->request('POST', '/api/v1/clients', [
            'name' => $name, 'token' => $token,
            'max_tunnels' => $maxTunnels, 'max_traffic_bytes' => $maxTrafficBytes,
        ]);
    }
    public function listClients()
    {
        return $this->request('GET', '/api/v1/clients');
    }
    public function getTraffic($name)
    {
        return $this->request('GET', '/api/v1/clients/' . rawurlencode($name) . '/traffic');
    }
    public function deleteClient($name)
    {
        return $this->request('DELETE', '/api/v1/clients/' . rawurlencode($name));
    }

    // ==================== 隧道管理（DB 驱动） ====================
    public function createProxy($name, $type, $remotePort, $localPort, $localAddr, $clientName)
    {
        return $this->request('POST', '/api/v1/proxies', [
            'name' => $name, 'type' => $type,
            'remote_port' => $remotePort, 'local_port' => $localPort,
            'local_addr' => $localAddr, 'client_name' => $clientName,
        ]);
    }
    public function listProxies($filters = [])
    {
        $q = http_build_query($filters);
        return $this->request('GET', '/api/v1/proxies' . ($q ? '?' . $q : ''));
    }
    public function getProxy($name)
    {
        return $this->request('GET', '/api/v1/proxies/' . rawurlencode($name));
    }
    public function updateProxy($name, array $patch)
    {
        return $this->request('PATCH', '/api/v1/proxies/' . rawurlencode($name), $patch);
    }
    public function deleteProxy($name)
    {
        return $this->request('DELETE', '/api/v1/proxies/' . rawurlencode($name));
    }
    public function enableProxy($name)
    {
        return $this->request('POST', '/api/v1/proxies/' . rawurlencode($name) . '/enable');
    }
    public function disableProxy($name)
    {
        return $this->request('POST', '/api/v1/proxies/' . rawurlencode($name) . '/disable');
    }
    public function closeProxy($name)
    {
        return $this->request('POST', '/api/v1/proxies/close', ['name' => $name]);
    }

    // ==================== API Key 管理 ====================
    public function listAPIKeys()
    {
        return $this->request('GET', '/api/v1/api-keys');
    }
    public function createAPIKey($key, $note = '')
    {
        return $this->request('POST', '/api/v1/api-keys', ['key' => $key, 'note' => $note]);
    }
    public function deleteAPIKey($key)
    {
        return $this->request('DELETE', '/api/v1/api-keys/' . rawurlencode($key));
    }
}

// ==================== CLI 演示 ====================
if (PHP_SAPI === 'cli' && isset($argv[1]) && $argv[1] === 'demo') {
    [$_, $_, $baseURL, $apiKey, $action] = array_pad($argv, 5, '');
    if (!$baseURL || !$apiKey || !$action) {
        echo "用法: php nexuslink.php demo <baseURL> <apiKey> <action> [参数...]\n";
        echo "actions: create-client NAME TOKEN [max_tunnels] [max_traffic] | list-clients | traffic NAME | delete-client NAME | create-proxy NAME TYPE REMOTE_PORT LOCAL_PORT LOCAL_ADDR CLIENT | list-proxies | delete-proxy NAME | disable-proxy NAME | list-keys | create-key KEY [note]\n";
        exit(1);
    }
    try {
        $api = new NexusLinkClient($baseURL, $apiKey);
        $rest = array_slice($argv, 5);
        switch ($action) {
            case 'create-client':
                print_r($api->createClient($rest[0], $rest[1], (int)($rest[2] ?? 0), (int)($rest[3] ?? 0)));
                break;
            case 'list-clients':
                print_r($api->listClients());
                break;
            case 'traffic':
                print_r($api->getTraffic($rest[0]));
                break;
            case 'delete-client':
                print_r($api->deleteClient($rest[0]));
                break;
            case 'create-proxy':
                print_r($api->createProxy($rest[0], $rest[1], (int)$rest[2], (int)$rest[3], $rest[4], $rest[5]));
                break;
            case 'list-proxies':
                print_r($api->listProxies());
                break;
            case 'proxy':
                print_r($api->getProxy($rest[0]));
                break;
            case 'update-proxy': // name field value
                print_r($api->updateProxy($rest[0], [$rest[1] => $rest[2]]));
                break;
            case 'delete-proxy':
                print_r($api->deleteProxy($rest[0]));
                break;
            case 'disable-proxy':
                print_r($api->disableProxy($rest[0]));
                break;
            case 'list-keys':
                print_r($api->listAPIKeys());
                break;
            case 'create-key':
                print_r($api->createAPIKey($rest[0], $rest[1] ?? ''));
                break;
            default:
                echo "未知 action: $action\n";
                exit(1);
        }
    } catch (Exception $e) {
        echo '错误: ' . $e->getMessage() . "\n";
        exit(1);
    }
}

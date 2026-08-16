// NexusLink 开放 API v1 Node.js 客户端
// 零第三方依赖（Node 18+ 内置 fetch）
//
// 使用：
//   const { NexusLinkClient } = require('./nexuslink.js');
//   const api = new NexusLinkClient('http://SERVER:7001', 'dev_api_key_789');
//   await api.createClient('customer-a', 'tok_a_1', 3, 0);
//   await api.createProxy('web', 'tcp', 8099, 9000, '127.0.0.1', 'customer-a');

class NexusLinkClient {
  /**
   * @param {string} baseURL 形如 http://SERVER:7001
   * @param {string} apiKey  X-API-Key
   */
  constructor(baseURL, apiKey) {
    this.baseURL = baseURL.replace(/\/+$/, '');
    this.apiKey = apiKey;
  }

  async _req(method, path, body) {
    const headers = {
      'X-API-Key': this.apiKey,
      'Content-Type': 'application/json',
    };
    const resp = await fetch(this.baseURL + path, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(`API ${resp.status}: ${data.error || resp.statusText}`);
    }
    if (data.success === false) {
      throw new Error(data.error || 'API error');
    }
    return data;
  }

  // ==================== 客户端管理 ====================
  createClient(name, token, maxTunnels = 0, maxTrafficBytes = 0) {
    return this._req('POST', '/api/v1/clients', { name, token, max_tunnels: maxTunnels, max_traffic_bytes: maxTrafficBytes });
  }
  listClients() {
    return this._req('GET', '/api/v1/clients');
  }
  getTraffic(name) {
    return this._req('GET', `/api/v1/clients/${encodeURIComponent(name)}/traffic`);
  }
  deleteClient(name) {
    return this._req('DELETE', `/api/v1/clients/${encodeURIComponent(name)}`);
  }

  // ==================== 隧道管理（DB 驱动） ====================
  createProxy(name, type, remotePort, localPort, localAddr, clientName) {
    return this._req('POST', '/api/v1/proxies', {
      name, type, remote_port: remotePort, local_port: localPort, local_addr: localAddr, client_name: clientName,
    });
  }
  listProxies() {
    return this._req('GET', '/api/v1/proxies');
  }
  deleteProxy(name) {
    return this._req('DELETE', `/api/v1/proxies/${encodeURIComponent(name)}`);
  }
  enableProxy(name) {
    return this._req('POST', `/api/v1/proxies/${encodeURIComponent(name)}/enable`);
  }
  disableProxy(name) {
    return this._req('POST', `/api/v1/proxies/${encodeURIComponent(name)}/disable`);
  }
  closeProxy(name) {
    return this._req('POST', '/api/v1/proxies/close', { name });
  }

  // ==================== API Key 管理 ====================
  listAPIKeys() {
    return this._req('GET', '/api/v1/api-keys');
  }
  createAPIKey(key, note = '') {
    return this._req('POST', '/api/v1/api-keys', { key, note });
  }
  deleteAPIKey(key) {
    return this._req('DELETE', `/api/v1/api-keys/${encodeURIComponent(key)}`);
  }
}

module.exports = { NexusLinkClient };

// ==================== CLI 演示 ====================
if (require.main === module) {
  const [,, baseURL, apiKey, action, ...rest] = process.argv;
  if (!baseURL || !apiKey || !action) {
    console.log('用法: node nexuslink.js <baseURL> <apiKey> <action> [参数...]');
    console.log('actions: create-client NAME TOKEN [max_tunnels] [max_traffic] | list-clients | traffic NAME | delete-client NAME | create-proxy NAME TYPE REMOTE_PORT LOCAL_PORT LOCAL_ADDR CLIENT | list-proxies | delete-proxy NAME | disable-proxy NAME | list-keys | create-key KEY [note]');
    process.exit(1);
  }
  const api = new NexusLinkClient(baseURL, apiKey);
  (async () => {
    switch (action) {
      case 'create-client':
        console.log(await api.createClient(rest[0], rest[1], Number(rest[2] || 0), Number(rest[3] || 0)));
        break;
      case 'list-clients':
        console.log(JSON.stringify(await api.listClients(), null, 2));
        break;
      case 'traffic':
        console.log(JSON.stringify(await api.getTraffic(rest[0]), null, 2));
        break;
      case 'delete-client':
        console.log(await api.deleteClient(rest[0]));
        break;
      case 'create-proxy':
        console.log(await api.createProxy(rest[0], rest[1], Number(rest[2]), Number(rest[3]), rest[4], rest[5]));
        break;
      case 'list-proxies':
        console.log(JSON.stringify(await api.listProxies(), null, 2));
        break;
      case 'delete-proxy':
        console.log(await api.deleteProxy(rest[0]));
        break;
      case 'disable-proxy':
        console.log(await api.disableProxy(rest[0]));
        break;
      case 'list-keys':
        console.log(JSON.stringify(await api.listAPIKeys(), null, 2));
        break;
      case 'create-key':
        console.log(await api.createAPIKey(rest[0], rest[1] || ''));
        break;
      default:
        console.error('未知 action:', action);
        process.exit(1);
    }
  })().catch((e) => { console.error('错误:', e.message); process.exit(1); });
}

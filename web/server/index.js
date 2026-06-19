const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const YAML = require('yaml');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 9527;

// 路径配置
const BASE_DIR = path.resolve(__dirname, '..');
const BIN_DIR = path.join(BASE_DIR, 'bin');
const CONFIG_DIR = path.join(BASE_DIR, 'config');
const PUBLIC_DIR = path.join(__dirname, 'public');

// 认证配置
const AUTH = {
  password: 'admin123', // 默认密码
  token: null // 登录后生成的token
};

// 生成随机token
function generateToken() {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// 认证中间件
function authMiddleware(req, res, next) {
  // 跳过静态文件和登录接口
  if (req.path === '/' || req.path.startsWith('/index.html') || req.path === '/api/login') {
    return next();
  }
  
  const token = req.headers['authorization'] || req.query.token;
  if (AUTH.token && token === AUTH.token) {
    next();
  } else {
    res.status(401).json({ success: false, message: '未授权' });
  }
}

// 中间件
app.use(cors());
app.use(express.json());

// 静态文件服务（放在认证中间件之前，确保登录页面可以访问）
app.use(express.static(PUBLIC_DIR));

// 认证中间件（已禁用，本地管理面板无需登录）
// API 认证中间件（登录接口除外）
app.use('/api', (req, res, next) => {
  if (req.path === '/login') return next();
  authMiddleware(req, res, next);
});

// 进程管理
const processes = {
  server: null,
  client: null
};

// 日志缓存
const MAX_LOG_LINES = 200;
const logCache = {
  server: [],
  client: []
};

// WebSocket
const wss = new WebSocket.Server({ noServer: true });
const clients = new Set();

wss.on('connection', (ws) => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
});

function broadcast(data) {
  const msg = JSON.stringify(data);
  clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  });
}

function broadcastStatus() {
  broadcast({
    type: 'status',
    server: getServiceStatus('server'),
    client: getServiceStatus('client')
  });
}

function broadcastLog(type, line) {
  broadcast({
    type: 'log',
    service: type,
    line: line
  });
}

// 读取配置
function readConfig(type) {
  const configFile = path.join(CONFIG_DIR, `${type}.yaml`);
  if (fs.existsSync(configFile)) {
    try {
      return YAML.parse(fs.readFileSync(configFile, 'utf8'));
    } catch (e) {
      return null;
    }
  }
  return null;
}

// 写入配置
function writeConfig(type, config) {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }
  const configFile = path.join(CONFIG_DIR, `${type}.yaml`);
  fs.writeFileSync(configFile, YAML.stringify(config));
}

// 获取服务状态
function getServiceStatus(type) {
  const proc = processes[type];
  const config = readConfig(type);
  return {
    running: proc !== null,
    pid: proc?.pid || null,
    config: config
  };
}

// 启动服务
function startService(type) {
  if (processes[type]) {
    return { success: false, message: '服务已在运行' };
  }

  const binPath = path.join(BIN_DIR, `nexuslink-${type}`);
  const configPath = path.join(CONFIG_DIR, `${type}.yaml`);

  if (!fs.existsSync(binPath)) {
    return { success: false, message: `二进制文件不存在: ${binPath}` };
  }

  try {
    const proc = spawn(binPath, ['-c', configPath], {
      cwd: BASE_DIR,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    proc.stdout.on('data', (data) => {
      const lines = data.toString().split('\n').filter(l => l.trim());
      lines.forEach(line => addLog(type, line));
    });

    proc.stderr.on('data', (data) => {
      const lines = data.toString().split('\n').filter(l => l.trim());
      lines.forEach(line => addLog(type, `[ERR] ${line}`));
    });

    proc.on('exit', (code) => {
      addLog(type, `进程退出，代码: ${code}`);
      processes[type] = null;
      broadcastStatus();
    });

    processes[type] = proc;
    addLog(type, `进程启动成功，PID: ${proc.pid}`);
    broadcastStatus();
    return { success: true, pid: proc.pid };
  } catch (e) {
    return { success: false, message: e.message };
  }
}

// 停止服务
function stopService(type) {
  const proc = processes[type];
  if (!proc) {
    return { success: false, message: '服务未运行' };
  }

  try {
    proc.kill('SIGTERM');
    addLog(type, '正在停止服务...');
    setTimeout(() => {
      if (processes[type]) {
        proc.kill('SIGKILL');
      }
    }, 3000);
    return { success: true };
  } catch (e) {
    return { success: false, message: e.message };
  }
}

// 添加日志
function addLog(type, line) {
  const timestamp = new Date().toLocaleString('zh-CN');
  const logLine = `[${timestamp}] ${line}`;
  logCache[type].push(logLine);
  if (logCache[type].length > MAX_LOG_LINES) {
    logCache[type].shift();
  }
  broadcastLog(type, logLine);
}

// ========== API 接口 ==========

// 登录
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (password === AUTH.password) {
    AUTH.token = generateToken();
    res.json({ success: true, token: AUTH.token });
  } else {
    res.status(401).json({ success: false, message: '密码错误' });
  }
});

// 登出
app.post('/api/logout', (req, res) => {
  AUTH.token = null;
  res.json({ success: true });
});

// 系统信息
app.get('/api/system', (req, res) => {
  const serverBin = path.join(BIN_DIR, 'nexuslink-server');
  const clientBin = path.join(BIN_DIR, 'nexuslink-client');
  
  res.json({
    version: 'v0.2.0.beta',
    name: 'NexusLink Web',
    description: '打通内外网的桥梁',
    binaries: {
      server: fs.existsSync(serverBin) ? fs.statSync(serverBin).size : 0,
      client: fs.existsSync(clientBin) ? fs.statSync(clientBin).size : 0
    },
    uptime: process.uptime()
  });
});

// 状态查询
app.get('/api/status', (req, res) => {
  res.json({
    server: getServiceStatus('server'),
    client: getServiceStatus('client')
  });
});

// 服务端状态
app.get('/api/status/server', (req, res) => {
  res.json(getServiceStatus('server'));
});

// 客户端状态
app.get('/api/status/client', (req, res) => {
  res.json(getServiceStatus('client'));
});

// 启动服务端
app.post('/api/server/start', (req, res) => {
  const result = startService('server');
  res.json(result);
});

// 停止服务端
app.post('/api/server/stop', (req, res) => {
  const result = stopService('server');
  res.json(result);
});

// 启动客户端
app.post('/api/client/start', (req, res) => {
  const result = startService('client');
  res.json(result);
});

// 停止客户端
app.post('/api/client/stop', (req, res) => {
  const result = stopService('client');
  res.json(result);
});

// 获取服务端配置
app.get('/api/config/server', (req, res) => {
  const config = readConfig('server');
  res.json({ success: true, config });
});

// 保存服务端配置
app.post('/api/config/server', (req, res) => {
  try {
    writeConfig('server', req.body);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// 获取客户端配置
app.get('/api/config/client', (req, res) => {
  const config = readConfig('client');
  res.json({ success: true, config });
});

// 保存客户端配置
app.post('/api/config/client', (req, res) => {
  try {
    writeConfig('client', req.body);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// 获取代理列表
app.get('/api/proxies', (req, res) => {
  const config = readConfig('client');
  res.json({ success: true, proxies: config?.proxies || {} });
});

// 添加代理
app.post('/api/proxies', (req, res) => {
  try {
    const { name, type, port, localaddr, localport } = req.body;
    const config = readConfig('client') || { proxies: {} };
    if (!config.proxies) config.proxies = {};
    
    config.proxies[name] = {
      type: type || 'tcp',
      port: parseInt(port),
      localaddr: localaddr || '127.0.0.1',
      localport: parseInt(localport)
    };
    
    writeConfig('client', config);
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// 删除代理
app.delete('/api/proxies/:name', (req, res) => {
  try {
    const { name } = req.params;
    const config = readConfig('client');
    if (config?.proxies?.[name]) {
      delete config.proxies[name];
      writeConfig('client', config);
    }
    res.json({ success: true });
  } catch (e) {
    res.json({ success: false, message: e.message });
  }
});

// 获取日志
app.get('/api/logs/:type', (req, res) => {
  const { type } = req.params;
  res.json({ success: true, logs: logCache[type] || [] });
});

// 清空日志
app.delete('/api/logs/:type', (req, res) => {
  const { type } = req.params;
  logCache[type] = [];
  res.json({ success: true });
});

// 初始化默认配置
function initDefaultConfig() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
  }

  if (!readConfig('server')) {
    writeConfig('server', {
      bind_addr: '0.0.0.0',
      bind_port: 7000,
      token: 'nexuslink-default-token'
    });
  }

  if (!readConfig('client')) {
    writeConfig('client', {
      server_ip: '127.0.0.1',
      server_port: 7000,
      token: 'nexuslink-default-token',
      proxies: {
        web: {
          type: 'tcp',
          port: 8080,
          localaddr: '127.0.0.1',
          localport: 80
        },
        ssh: {
          type: 'tcp',
          port: 6000,
          localaddr: '127.0.0.1',
          localport: 22
        }
      }
    });
  }
}

// 启动服务器
initDefaultConfig();

const server = app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║                                              ║
║   🚀 NexusLink Web 管理面板已启动            ║
║                                              ║
║   🌐 地址: http://localhost:${PORT}             ║
║                                              ║
║   🔐 默认密码: admin123                      ║
║                                              ║
║   版本: v0.2.0.beta                          ║
║   内核: C语言自主引擎                        ║
║                                              ║
╚══════════════════════════════════════════════╝
  `);
});

// WebSocket升级
server.on('upgrade', (request, socket, head) => {
  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit('connection', ws, request);
  });
});

// 定时广播状态
setInterval(broadcastStatus, 2000);

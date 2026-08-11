/* ============================================================
   NexusLink Web 面板 · 主应用
   状态管理 + API 方法 + 三页模板组合（概览 / 隧道预览 / 安全中心）
   ============================================================ */
(function () {
    'use strict';

    const app = Vue.createApp({
        data() {
            return {
                loggedIn: false,
                page: 'dashboard',
                loginError: '',
                csrfToken: '',
                status: {
                    running: true,
                    clientCount: 0,
                    proxyCount: 0,
                    bindPort: '--',
                    version: 'v0.3.7',
                    proxies: []
                },
                sec: {
                    session_timeout_min: 30,
                    rate_limit_max: 5,
                    rate_limit_lock_min: 15,
                    custom_csp: '',
                    csrf_protection: true,
                    security_headers: true,
                    httponly_cookie: true,
                    samesite_cookie: true
                },
                secStatus: { active_sessions: 0, locked_ips: [] },
                events: [],
                pw: { current: '', next: '', confirm: '' },
                hints: { sec: '', secClass: '', pw: '', pwClass: '' }
            };
        },
        computed: {
            proxies() { return this.status.proxies || []; }
        },
        mounted() {
            this.checkLogin();
            setInterval(this.loadData, 30000);
        },
        methods: {
            /* ---------- 认证 ---------- */
            async checkLogin() {
                try {
                    const res = await fetch('/api/status', { credentials: 'same-origin' });
                    if (res.ok) { this.loggedIn = true; this.loadData(); }
                } catch (e) {}
            },
            async login(pwd) {
                try {
                    const res = await fetch('/api/login', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'same-origin',
                        body: JSON.stringify({ password: pwd })
                    });
                    const d = await res.json();
                    if (res.ok && d.success) {
                        this.csrfToken = d.csrf_token;
                        this.loggedIn = true;
                        this.loginError = '';
                        this.loadData();
                    } else {
                        this.loginError = d.error || '登录失败';
                    }
                } catch (e) { this.loginError = '网络错误'; }
            },
            async logout() {
                try {
                    await fetch('/api/logout', {
                        method: 'POST',
                        headers: { 'X-CSRF-Token': this.csrfToken },
                        credentials: 'same-origin'
                    });
                } catch (e) {}
                location.reload();
            },

            /* ---------- 导航 ---------- */
            switchPage(p) {
                this.page = p;
                if (p === 'security') {
                    this.loadSecurity();
                    this.loadSecurityStatus();
                    this.loadSecurityEvents();
                }
            },

            /* ---------- 数据加载 ---------- */
            async loadData() {
                try {
                    const res = await fetch('/api/status', { credentials: 'same-origin' });
                    if (res.status === 401) { this.logout(); return; }
                    this.status = await res.json();
                } catch (e) {}
            },
            async loadSecurity() {
                try {
                    const res = await fetch('/api/security', { credentials: 'same-origin' });
                    if (res.status === 401) { this.logout(); return; }
                    this.sec = await res.json();
                } catch (e) {}
            },
            async saveSecurity() {
                try {
                    const res = await fetch('/api/security', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrfToken },
                        credentials: 'same-origin',
                        body: JSON.stringify(this.sec)
                    });
                    const d = await res.json();
                    this.hints.sec = d.success ? '已保存' : (d.error || '保存失败');
                    this.hints.secClass = d.success ? '' : 'err';
                } catch (e) { this.hints.sec = '网络错误'; this.hints.secClass = 'err'; }
            },
            async loadSecurityStatus() {
                try {
                    const res = await fetch('/api/security-status', { credentials: 'same-origin' });
                    if (res.status === 401) { this.logout(); return; }
                    this.secStatus = await res.json();
                } catch (e) {}
            },
            async unlockIP(ip) {
                if (!confirm('确定解锁 ' + ip + ' 吗？')) return;
                try {
                    await fetch('/api/security-unlock', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrfToken },
                        credentials: 'same-origin',
                        body: JSON.stringify({ ip })
                    });
                    this.loadSecurityStatus();
                } catch (e) {}
            },
            async loadSecurityEvents() {
                try {
                    const res = await fetch('/api/security-events', { credentials: 'same-origin' });
                    if (res.status === 401) { this.logout(); return; }
                    this.events = (await res.json()).events || [];
                } catch (e) {}
            },

            /* ---------- 修改密码 ---------- */
            async changePassword() {
                if (!this.pw.current || !this.pw.next) { this.hints.pw = '请填写完整'; this.hints.pwClass = 'err'; return; }
                if (this.pw.next.length < 6) { this.hints.pw = '新密码至少 6 位'; this.hints.pwClass = 'err'; return; }
                if (this.pw.next !== this.pw.confirm) { this.hints.pw = '两次输入不一致'; this.hints.pwClass = 'err'; return; }
                try {
                    const res = await fetch('/api/change-password', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': this.csrfToken },
                        credentials: 'same-origin',
                        body: JSON.stringify({ current_password: this.pw.current, new_password: this.pw.next })
                    });
                    const d = await res.json();
                    if (d.success) { alert('密码已修改，请重新登录'); this.logout(); }
                    else { this.hints.pw = d.error || '修改失败'; this.hints.pwClass = 'err'; }
                } catch (e) { this.hints.pw = '网络错误'; this.hints.pwClass = 'err'; }
            },

            /* ---------- 工具 ---------- */
            fmtBytes(b) {
                if (!b) return '0B';
                const units = ['B', 'KB', 'MB', 'GB', 'TB'];
                let i = 0, v = b;
                while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
                return v.toFixed(v >= 100 || i === 0 ? 0 : 1) + units[i];
            },
            typeLabel(t) { return (t || 'tcp').toUpperCase(); }
        },
        template: `
        <!-- 登录页 -->
        <nx-login-card v-if="!loggedIn" :error="loginError" @submit="login"></nx-login-card>

        <!-- 主界面 -->
        <div v-else class="main-page">
            <nx-sidebar :page="page" :version="status.version" @switch="switchPage" @logout="logout"></nx-sidebar>
            <main class="content">
                <div class="container">

                    <!-- ===== 概览 ===== -->
                    <div v-if="page==='dashboard'">
                        <nx-page-head title="概览" sub="实时掌握服务状态与安全防护"></nx-page-head>
                        <div class="stats-grid">
                            <nx-stat-card label="服务状态" :value="status.running ? '运行中' : '已停止'" :tone="status.running ? 'online' : 'offline'"></nx-stat-card>
                            <nx-stat-card label="客户端连接" :value="status.clientCount"></nx-stat-card>
                            <nx-stat-card label="隧道数量" :value="status.proxyCount"></nx-stat-card>
                            <nx-stat-card label="监听端口" :value="status.bindPort" small></nx-stat-card>
                        </div>
                        <nx-panel title="安全防护" sub="全部防护项已开启">
                            <div class="security-features">
                                <div class="security-feature" v-for="f in ['密码哈希加密','防暴力破解','登录失败锁定','CSRF 防护','会话超时','安全响应头','HttpOnly Cookie']" :key="f">{{ f }}</div>
                            </div>
                        </nx-panel>
                        <nx-panel title="隧道列表">
                            <div class="table-wrap">
                                <table class="data-table">
                                    <thead><tr><th>隧道名称</th><th>类型</th><th>远程端口</th><th>流量</th><th>状态</th></tr></thead>
                                    <tbody>
                                        <tr v-if="!proxies.length"><td colspan="5"><nx-empty text="暂无隧道"></nx-empty></td></tr>
                                        <tr v-for="p in proxies" :key="p.name">
                                            <td class="cell-mono">{{ p.name }}</td>
                                            <td>{{ typeLabel(p.type) }}</td>
                                            <td class="cell-mono">{{ p.remotePort }}</td>
                                            <td class="cell-mono">{{ fmtBytes(p.bytesIn) }} / {{ fmtBytes(p.bytesOut) }}</td>
                                            <td><nx-badge :on="p.active"></nx-badge></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </nx-panel>
                    </div>

                    <!-- ===== 隧道预览 ===== -->
                    <div v-else-if="page==='proxies'">
                        <nx-page-head title="隧道预览" sub="全部穿透隧道一览"></nx-page-head>
                        <nx-panel title="全部隧道">
                            <div class="table-wrap">
                                <table class="data-table">
                                    <thead><tr><th>隧道名称</th><th>类型</th><th>远程端口</th><th>本地地址</th><th>本地端口</th><th>流量</th><th>状态</th></tr></thead>
                                    <tbody>
                                        <tr v-if="!proxies.length"><td colspan="7"><nx-empty text="暂无隧道"></nx-empty></td></tr>
                                        <tr v-for="p in proxies" :key="p.name">
                                            <td class="cell-mono">{{ p.name }}</td>
                                            <td>{{ typeLabel(p.type) }}</td>
                                            <td class="cell-mono">{{ p.remotePort }}</td>
                                            <td class="cell-mono">{{ p.localAddr || '--' }}</td>
                                            <td class="cell-mono">{{ p.localPort || '--' }}</td>
                                            <td class="cell-mono">{{ fmtBytes(p.bytesIn) }} / {{ fmtBytes(p.bytesOut) }}</td>
                                            <td><nx-badge :on="p.active"></nx-badge></td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </nx-panel>
                    </div>

                    <!-- ===== 安全中心 ===== -->
                    <div v-else>
                        <nx-page-head title="安全中心" sub="可调整安全防护策略与实时安全监控"></nx-page-head>

                        <nx-panel title="安全策略设置" sub="保存后实时生效">
                            <div class="form-grid">
                                <div class="form-group"><label>会话超时（分钟）</label><input type="number" v-model.number="sec.session_timeout_min" min="1" max="1440"></div>
                                <div class="form-group"><label>登录失败锁定阈值（次）</label><input type="number" v-model.number="sec.rate_limit_max" min="1" max="100"></div>
                                <div class="form-group"><label>锁定时长（分钟）</label><input type="number" v-model.number="sec.rate_limit_lock_min" min="1" max="1440"></div>
                                <div class="form-group"><label>自定义 CSP 响应头（可选）</label><input type="text" v-model="sec.custom_csp" placeholder="留空使用默认策略"></div>
                            </div>
                            <div class="toggle-grid">
                                <nx-switch v-model="sec.csrf_protection" label="CSRF 防护"></nx-switch>
                                <nx-switch v-model="sec.security_headers" label="安全响应头"></nx-switch>
                                <nx-switch v-model="sec.httponly_cookie" label="HttpOnly Cookie"></nx-switch>
                                <nx-switch v-model="sec.samesite_cookie" label="SameSite Cookie"></nx-switch>
                            </div>
                            <div class="form-actions">
                                <button class="btn btn-primary" @click="saveSecurity">保存安全设置</button>
                                <span class="save-hint" :class="hints.secClass">{{ hints.sec }}</span>
                            </div>
                        </nx-panel>

                        <nx-panel title="底层加密保障" sub="始终开启，不可关闭">
                            <div class="sec-row"><span class="sec-label">密码哈希存储（SHA-256 多次迭代）</span><span class="sec-val">常开</span></div>
                            <div class="sec-row"><span class="sec-label">密码加盐</span><span class="sec-val">常开</span></div>
                            <div class="sec-row"><span class="sec-label">常量时间比较（防时序攻击）</span><span class="sec-val">常开</span></div>
                        </nx-panel>

                        <nx-panel title="实时安全状态">
                            <div class="kv"><span class="kv-k">当前活动会话</span><span class="kv-v num">{{ secStatus.active_sessions }}</span></div>
                            <div class="kv"><span class="kv-k">被锁定 IP 数</span><span class="kv-v num">{{ secStatus.locked_ips.length }}</span></div>
                            <div style="margin-top:12px;">
                                <div v-if="!secStatus.locked_ips.length" style="color:var(--text-3);font-size:13px;">无被锁定的 IP</div>
                                <div v-for="x in secStatus.locked_ips" :key="x.ip" class="lock-row">
                                    <span class="cell-mono">{{ x.ip }}</span>
                                    <span style="font-size:12px;opacity:.8">约 {{ x.unlock_at }} 解锁</span>
                                    <button class="btn btn-secondary" @click="unlockIP(x.ip)">解锁</button>
                                </div>
                            </div>
                        </nx-panel>

                        <nx-panel title="安全事件">
                            <div v-if="!events.length"><nx-empty text="暂无安全事件"></nx-empty></div>
                            <div v-for="e in events" :key="e.time + e.message" class="event-row">
                                <span class="event-time">{{ e.time }}</span>
                                <span class="log-level" :class="e.level">[{{ e.level.toUpperCase() }}]</span>
                                <span class="event-msg">{{ e.message }}</span>
                            </div>
                        </nx-panel>

                        <nx-panel title="修改管理密码">
                            <div class="form-grid">
                                <div class="form-group"><label>当前密码</label><input type="password" v-model="pw.current" autocomplete="current-password"></div>
                                <div class="form-group"><label>新密码（至少 6 位）</label><input type="password" v-model="pw.next" autocomplete="new-password"></div>
                                <div class="form-group" style="grid-column:1/-1"><label>确认新密码</label><input type="password" v-model="pw.confirm" autocomplete="new-password"></div>
                            </div>
                            <div class="form-actions">
                                <button class="btn btn-primary" @click="changePassword">修改密码</button>
                                <span class="save-hint" :class="hints.pwClass">{{ hints.pw }}</span>
                            </div>
                        </nx-panel>
                    </div>

                </div>
                <div class="footer">NexusLink · 安全内网穿透平台</div>
            </main>
        </div>`
    });

    // 注册全局组件
    Object.entries(window.NexusLinkComponents || {}).forEach(([name, comp]) => app.component(name, comp));

    app.mount('#app');
})();

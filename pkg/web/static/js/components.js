/* ============================================================
   NexusLink Web 面板 · 组件定义表
   由 app.js 统一注册（window.NexusLinkComponents 导出）
   组件：登录卡 / 侧边栏 / 页面头 / 统计卡 / 面板 / 徽章 / 开关 / 空态
   ============================================================ */
window.NexusLinkComponents = {
    /* ---------- 登录卡片 ---------- */
    'nx-login-card': {
        props: ['error'],
        emits: ['submit'],
        data() { return { password: '' }; },
        methods: { onSubmit() { this.$emit('submit', this.password); } },
        template: `
        <div class="login-page">
            <div class="login-box">
                <div class="brand">
                    <div class="brand-name">NexusLink</div>
                    <div class="brand-sub">安全内网穿透 · 隧道一键直达</div>
                </div>
                <div class="form-group">
                    <label>管理密码</label>
                    <input type="password" v-model="password" @keyup.enter="onSubmit"
                           placeholder="请输入管理密码" autocomplete="current-password" autofocus>
                </div>
                <button class="btn btn-primary btn-block" @click="onSubmit">登 录</button>
                <div class="error-msg" v-if="error">{{ error }}</div>
                <div class="login-note">
                    <strong>安全模式已启用</strong>
                    密码加密 · 防暴力破解 · 登录锁定 · 会话超时
                </div>
            </div>
        </div>`
    },

    /* ---------- 侧边栏 ---------- */
    'nx-sidebar': {
        props: ['page', 'version'],
        emits: ['switch', 'logout'],
        methods: {
            isActive(p) { return this.page === p; },
            onSwitch(p) { this.$emit('switch', p); }
        },
        template: `
        <aside class="sidebar">
            <div class="side-brand">
                <div class="side-name">NexusLink</div>
                <div class="side-sub">安全内网穿透</div>
            </div>
            <nav class="side-nav">
                <div class="nav-item" :class="{active: isActive('dashboard')}" @click="onSwitch('dashboard')">概览</div>
                <div class="nav-item" :class="{active: isActive('proxies')}" @click="onSwitch('proxies')">隧道预览</div>
                <div class="nav-item" :class="{active: isActive('security')}" @click="onSwitch('security')">安全中心</div>
            </nav>
            <div class="side-footer">
                <span class="version-pill">{{ version || 'v0.3.7' }}</span>
                <button class="logout-btn" @click="$emit('logout')">退出</button>
            </div>
        </aside>`
    },

    /* ---------- 页面头部 ---------- */
    'nx-page-head': {
        props: ['title', 'sub'],
        template: `
        <div class="page-head">
            <h2>{{ title }}</h2>
            <p v-if="sub">{{ sub }}</p>
        </div>`
    },

    /* ---------- 统计卡片 ---------- */
    'nx-stat-card': {
        props: {
            label: String,
            value: [String, Number],
            tone: { type: String, default: '' },   // online | offline
            small: { type: Boolean, default: false }
        },
        template: `
        <div class="stat-card">
            <div class="stat-label">{{ label }}</div>
            <div class="stat-value num" :class="[tone, {small: small}]">{{ value }}</div>
        </div>`
    },

    /* ---------- 面板卡片 ---------- */
    'nx-panel': {
        props: {
            title: String,
            sub: { type: String, default: '' }
        },
        template: `
        <div class="panel">
            <template v-if="title">
                <div class="panel-title">{{ title }}</div>
                <div class="panel-sub" v-if="sub">{{ sub }}</div>
            </template>
            <slot></slot>
        </div>`
    },

    /* ---------- 状态徽章 ---------- */
    'nx-badge': {
        props: {
            on: { type: Boolean, default: false },
            text: { type: String, default: '' }
        },
        computed: {
            label() { return this.text || (this.on ? '运行中' : '未激活'); }
        },
        template: `<span class="badge" :class="on ? 'on' : 'off'">{{ label }}</span>`
    },

    /* ---------- 开关（v-model 兼容） ---------- */
    'nx-switch': {
        props: {
            modelValue: Boolean,
            label: { type: String, default: '' }
        },
        emits: ['update:modelValue'],
        template: `
        <label class="switch-row">
            <span>{{ label }}</span>
            <input type="checkbox" class="switch"
                   :checked="modelValue"
                   @change="$emit('update:modelValue', $event.target.checked)">
        </label>`
    },

    /* ---------- 空状态 ---------- */
    'nx-empty': {
        props: { text: { type: String, default: '暂无数据' } },
        template: `<div class="empty-state">{{ text }}</div>`
    }
};

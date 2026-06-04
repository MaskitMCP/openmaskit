/**
 * Shared utilities for OpenMaskit frontend
 * Eliminates duplication across targets.html, tools.html, marketplace.html
 */

// ---------------------------------------------------------------------------
// CSRF: monkey-patch window.fetch to attach X-CSRF-Token on same-origin
// mutating requests. The token is fetched lazily from /api/csrf and cached
// for the lifetime of the page. On a 403 with `error: "csrf_invalid"` we
// refetch the token once and retry — covers a server restart while the tab
// is still open.
// ---------------------------------------------------------------------------
(function installCsrfFetch() {
    if (typeof window === 'undefined' || !window.fetch) return;
    if (window.__openmaskitCsrfInstalled) return;
    window.__openmaskitCsrfInstalled = true;

    const MUTATING = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);
    const originalFetch = window.fetch.bind(window);
    let tokenPromise = null;

    function fetchToken() {
        if (tokenPromise === null) {
            tokenPromise = originalFetch('/api/csrf', { credentials: 'same-origin' })
                .then(r => (r.ok ? r.json() : { token: '' }))
                .then(d => d.token || '')
                .catch(() => '');
        }
        return tokenPromise;
    }

    function resetToken() {
        tokenPromise = null;
    }
    window.__openmaskitResetCsrf = resetToken;

    function isSameOrigin(url) {
        try {
            if (typeof url !== 'string') url = url.url || String(url);
            if (url.startsWith('/')) return true;
            const u = new URL(url, window.location.href);
            return u.origin === window.location.origin;
        } catch {
            return true;
        }
    }

    function methodOf(input, init) {
        const m = (init && init.method) || (input && input.method) || 'GET';
        return String(m).toUpperCase();
    }

    async function withToken(input, init, token) {
        const opts = Object.assign({}, init || {});
        const headers = new Headers(opts.headers || (input && input.headers) || {});
        if (token) headers.set('X-CSRF-Token', token);
        opts.headers = headers;
        return originalFetch(input, opts);
    }

    window.fetch = async function patchedFetch(input, init) {
        const method = methodOf(input, init);
        if (!MUTATING.has(method) || !isSameOrigin(input)) {
            return originalFetch(input, init);
        }
        let token = await fetchToken();
        let resp = await withToken(input, init, token);
        if (resp.status === 403) {
            // Possible CSRF token rotation (server restart). Refetch once and retry.
            try {
                const cloned = resp.clone();
                const body = await cloned.json();
                if (body && body.error === 'csrf_invalid') {
                    resetToken();
                    token = await fetchToken();
                    resp = await withToken(input, init, token);
                }
            } catch { /* not JSON / not our shape — return original 403 */ }
        }
        return resp;
    };
})();

// Agent configurations for integration snippets
const AGENTS = [
    { id: 'claude-code', label: 'Claude Code' },
    { id: 'cursor', label: 'Cursor' },
    { id: 'vscode', label: 'VS Code' },
    { id: 'windsurf', label: 'Windsurf' },
    { id: 'jetbrains', label: 'JetBrains' },
    { id: 'codex', label: 'Codex' },
    { id: 'opencode', label: 'OpenCode' },
];

// Shared config (loaded once per page from /api/config)
let _configPromise = null;

async function getConfig() {
    if (_configPromise === null) {
        _configPromise = fetch('/api/config')
            .then(r => r.json())
            .catch(() => ({ mcp_port: 9474, version_status: {} }));
    }
    return _configPromise;
}

/**
 * Get the MCP port from the API (cached)
 */
async function getMcpPort() {
    const cfg = await getConfig();
    return cfg.mcp_port ?? 9474;
}

window.OpenMaskitConfig = { get: getConfig };

/**
 * Build the full MCP URL for a target
 */
function buildMcpUrl(targetName, mcpPort) {
    return `http://localhost:${mcpPort}/${targetName}/mcp`;
}

/**
 * Check if agent supports a self-contained CLI integration.
 * Only true when a single command genuinely completes the setup — not when
 * the CLI requires a JSON file to already exist (e.g. `codex --mcp-config`).
 */
function hasCli(agentId) {
    return ['claude-code', 'vscode'].includes(agentId);
}

/**
 * Generate CLI integration snippet
 */
function getCliSnippet(targetName, mcpPort, agentId) {
    const url = buildMcpUrl(targetName, mcpPort);
    const name = `openmaskit-${targetName}`;

    switch (agentId) {
        case 'claude-code':
            return `claude mcp add --scope project ${name} --transport http ${url}`;
        case 'vscode':
            return `code --add-mcp '${JSON.stringify({ name, type: 'http', url })}'`;
        default:
            return '';
    }
}

/**
 * Generate JSON integration snippet
 */
function getJsonSnippet(targetName, mcpPort, agentId) {
    const url = buildMcpUrl(targetName, mcpPort);
    const name = targetName;

    switch (agentId) {
        case 'claude-code':
            return JSON.stringify({ mcpServers: { [name]: { type: 'streamable-http', url } } }, null, 2);
        case 'cursor':
            return JSON.stringify({ mcpServers: { [name]: { url } } }, null, 2);
        case 'vscode':
            return JSON.stringify({ servers: { [name]: { type: 'http', url } } }, null, 2);
        case 'windsurf':
            return JSON.stringify({ mcpServers: { [name]: { serverUrl: url } } }, null, 2);
        case 'jetbrains':
            return JSON.stringify({ servers: { [name]: { type: 'http', url } } }, null, 2);
        case 'codex':
            return JSON.stringify({ mcpServers: { [name]: { type: 'url', url } } }, null, 2);
        case 'opencode':
            return JSON.stringify({ mcp: { servers: { [name]: { type: 'streamable-http', url } } } }, null, 2);
        default:
            return '';
    }
}

/**
 * Get integration note/help text for agent
 */
function getIntegrationNote(agentId) {
    switch (agentId) {
        case 'claude-code':
            return 'Add to .mcp.json in your project root, or ~/.claude.json globally.';
        case 'cursor':
            return 'Add to .cursor/mcp.json in your project root.';
        case 'vscode':
            return 'Add to .vscode/mcp.json in your workspace.';
        case 'windsurf':
            return 'Add to ~/.codeium/windsurf/mcp_config.json.';
        case 'jetbrains':
            return 'Go to Settings > Tools > AI Assistant > MCP Servers, click \'+\', select \'As JSON\', and paste.';
        case 'codex':
            return 'Add to ~/.codex/config.json or pass via --mcp-config.';
        case 'opencode':
            return 'Add to your opencode.json config file.';
        default:
            return '';
    }
}

/**
 * Copy text to clipboard
 */
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        return false;
    }
}

/**
 * Onboarding state management
 */
const OnboardingHelper = {
    STORAGE_KEY: 'maskit_onboarding_state',

    getState() {
        try {
            const stored = localStorage.getItem(this.STORAGE_KEY);
            return stored ? JSON.parse(stored) : { completed: false, skipped: false, timestamp: null };
        } catch {
            return { completed: false, skipped: false, timestamp: null };
        }
    },

    markCompleted() {
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify({
                completed: true,
                skipped: false,
                timestamp: Date.now()
            }));
        } catch (e) {
            console.warn('Failed to save onboarding state:', e);
        }
    },

    markSkipped() {
        try {
            localStorage.setItem(this.STORAGE_KEY, JSON.stringify({
                completed: false,
                skipped: true,
                timestamp: Date.now()
            }));
        } catch (e) {
            console.warn('Failed to save onboarding state:', e);
        }
    },

    reset() {
        try {
            localStorage.removeItem(this.STORAGE_KEY);
        } catch (e) {
            console.warn('Failed to reset onboarding state:', e);
        }
    },

    shouldShow() {
        const state = this.getState();
        return !state.completed && !state.skipped;
    }
};

// Export onboarding helper
window.OnboardingHelper = OnboardingHelper;

/**
 * Create an integration helper mixin for Alpine.js
 * Usage: x-data="{ ...integrationHelper(), ...yourData }"
 */
function integrationHelper() {
    return {
        agents: AGENTS,
        integration: {
            visible: false,
            targetName: '',
            mcpPort: 9474,
            agent: 'claude-code',
            mode: 'cli',
            copied: false,
        },

        async openIntegration(target) {
            const mcpPort = await getMcpPort();
            this.integration = {
                visible: true,
                targetName: target.name,
                mcpPort,
                agent: 'claude-code',
                mode: hasCli('claude-code') ? 'cli' : 'json',
                copied: false,
            };
        },

        closeIntegration() {
            this.integration.visible = false;
        },

        integrationUrl() {
            return buildMcpUrl(this.integration.targetName, this.integration.mcpPort);
        },

        hasCli() {
            return hasCli(this.integration.agent);
        },

        getCliSnippet() {
            return getCliSnippet(this.integration.targetName, this.integration.mcpPort, this.integration.agent);
        },

        getSnippet() {
            return getJsonSnippet(this.integration.targetName, this.integration.mcpPort, this.integration.agent);
        },

        getNote() {
            return getIntegrationNote(this.integration.agent);
        },

        async copySnippet() {
            const text = this.integration.mode === 'cli' ? this.getCliSnippet() : this.getSnippet();
            const success = await copyToClipboard(text);
            if (success) {
                this.integration.copied = true;
                setTimeout(() => this.integration.copied = false, 2000);
            } else {
                this.showToast?.('Failed to copy to clipboard', 'error');
            }
        },
    };
}

/**
 * Global toast notification helper
 * Compatible with Alpine.js toast systems in pages
 */
/**
 * Render the global version-update banner.
 * - update_required (server says we're unsupported): red, non-dismissible.
 * - update_available (newer release exists, still supported): info, dismissible
 *   via localStorage keyed by latest_version so a new release re-shows it.
 */
const VERSION_DISMISS_KEY = 'openmaskit:dismissed_update';

function isUpdateDismissed(latest) {
    try {
        return localStorage.getItem(VERSION_DISMISS_KEY) === latest;
    } catch {
        return false;
    }
}

function dismissUpdate(latest) {
    try {
        localStorage.setItem(VERSION_DISMISS_KEY, latest);
    } catch {}
    const el = document.getElementById('version-banner');
    if (el) el.remove();
}
window.dismissUpdate = dismissUpdate;

async function renderVersionBanner() {
    const cfg = await getConfig();
    const vs = cfg.version_status || {};
    if (!vs.update_required && !vs.update_available) return;
    if (vs.update_available && !vs.update_required && isUpdateDismissed(vs.latest_version)) return;

    const required = !!vs.update_required;
    const banner = document.createElement('div');
    banner.id = 'version-banner';
    banner.className = 'version-banner ' + (required ? 'version-banner-warn' : 'version-banner-info');
    const message = required
        ? `OpenMaskit ${cfg.current_version} is no longer supported. Update to ${vs.latest_version || 'the latest version'} to install new servers.`
        : `OpenMaskit ${vs.latest_version} is available (you're on ${cfg.current_version}).`;
    banner.innerHTML = `
        <span class="version-banner-text">${message}</span>
        ${required ? '' : `<button type="button" class="version-banner-dismiss" aria-label="Dismiss" onclick="dismissUpdate('${vs.latest_version || ''}')">&times;</button>`}
    `;
    document.body.insertBefore(banner, document.body.firstChild);
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', renderVersionBanner);
} else {
    renderVersionBanner();
}

window.showToast = function(msg, type = 'success') {
    // Dispatch custom event that Alpine.js components can listen to
    const event = new CustomEvent('show-toast', {
        detail: { msg, type }
    });
    window.dispatchEvent(event);

    // Also try to call page-level showToast if available
    if (typeof window.pageShowToast === 'function') {
        window.pageShowToast(msg, type);
    }
};

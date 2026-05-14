/**
 * Shared utilities for Maskit frontend
 * Eliminates duplication across targets.html, tools.html, marketplace.html
 */

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

// MCP port cache (shared across all pages)
let _mcpPortCache = null;

/**
 * Get the MCP port from the API (cached)
 */
async function getMcpPort() {
    if (_mcpPortCache === null) {
        try {
            const res = await fetch('/api/config');
            const data = await res.json();
            _mcpPortCache = data.mcp_port;
        } catch {
            _mcpPortCache = 9474;
        }
    }
    return _mcpPortCache;
}

/**
 * Build the full MCP URL for a target
 */
function buildMcpUrl(targetName, mcpPort) {
    return `http://localhost:${mcpPort}/${targetName}/mcp`;
}

/**
 * Check if agent supports CLI integration
 */
function hasCli(agentId) {
    return ['claude-code', 'codex'].includes(agentId);
}

/**
 * Generate CLI integration snippet
 */
function getCliSnippet(targetName, mcpPort, agentId) {
    const url = buildMcpUrl(targetName, mcpPort);
    const name = `maskit-${targetName}`;

    switch (agentId) {
        case 'claude-code':
            return `claude mcp add --scope project ${name} --transport http ${url}`;
        case 'codex':
            return `codex --mcp-config mcp.json`;
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
            return 'Add to <code>.mcp.json</code> in your project root, or <code>~/.claude.json</code> globally.';
        case 'cursor':
            return 'Add to <code>.cursor/mcp.json</code> in your project root.';
        case 'vscode':
            return 'Add to <code>.vscode/mcp.json</code> in your workspace.';
        case 'windsurf':
            return 'Add to <code>~/.codeium/windsurf/mcp_config.json</code>.';
        case 'jetbrains':
            return 'Go to <code>Settings &gt; Tools &gt; AI Assistant &gt; MCP Servers</code>, click \'+\', select \'As JSON\', and paste.';
        case 'codex':
            return 'Add to <code>~/.codex/config.json</code> or pass via <code>--mcp-config</code>.';
        case 'opencode':
            return 'Add to your <code>opencode.json</code> config file.';
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

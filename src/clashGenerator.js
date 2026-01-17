/**
 * Clash YAML Generator - CF Workers Version
 */

export class ClashGenerator {
    constructor(config) {
        this.config = config;
    }

    generate(proxies, useMeta = false) {
        const proxyNames = proxies.map(p => p.name);
        const proxyGroups = this.generateProxyGroups(proxyNames);

        const config = {
            port: 7890,
            'socks-port': 7891,
            'allow-lan': false,
            mode: 'Rule',
            'log-level': 'info',
            'external-controller': '127.0.0.1:9090',
            dns: this.getDnsConfig(),
            proxies: proxies.map(p => this.cleanProxy(p)),
            'proxy-groups': proxyGroups,
            rules: useMeta ? this.generateRulesWithProviders() : this.generateRules()
        };

        if (useMeta) {
            config['rule-providers'] = this.generateRuleProviders();
        }

        return this.toYaml(config);
    }

    getDnsConfig() {
        return {
            enable: true,
            ipv6: false,
            'enhanced-mode': 'fake-ip',
            'fake-ip-range': '198.18.0.1/16',
            'fake-ip-filter': ['*.lan', '*.local', 'time.*.com', 'ntp.*.com', '+.pool.ntp.org'],
            'default-nameserver': ['223.5.5.5', '119.29.29.29'],
            nameserver: ['https://dns.alidns.com/dns-query', 'https://doh.pub/dns-query'],
            fallback: ['https://dns.cloudflare.com/dns-query', 'https://dns.google/dns-query'],
            'fallback-filter': { geoip: true, 'geoip-code': 'CN', ipcidr: ['240.0.0.0/4'] }
        };
    }

    generateProxyGroups(proxyNames) {
        const groups = [];

        for (const g of this.config.proxyGroups) {
            const group = { name: g.name, type: g.type };

            if (g.filter) {
                try {
                    const regex = new RegExp(g.filter, 'i');
                    const matched = proxyNames.filter(n => regex.test(n));
                    group.proxies = matched.length > 0 ? matched : ['DIRECT'];
                } catch {
                    group.proxies = ['DIRECT'];
                }
            } else if (g.proxies) {
                group.proxies = g.proxies;
            } else {
                group.proxies = proxyNames;
            }

            if (g.type === 'url-test' || g.type === 'fallback') {
                group.url = g.url || 'http://www.gstatic.com/generate_204';
                group.interval = g.interval || 300;
                if (g.tolerance) group.tolerance = g.tolerance;
            }

            groups.push(group);
        }

        return groups;
    }

    generateRules() {
        const rules = [];

        for (const rs of this.config.rulesets) {
            if (rs.isBuiltin) {
                if (rs.type === 'GEOIP') {
                    rules.push(`GEOIP,${rs.value},${rs.group}`);
                } else if (rs.type === 'FINAL') {
                    // Add at end
                }
            }
        }

        rules.push('MATCH,🐟 漏网之鱼');
        return rules;
    }

    generateRulesWithProviders() {
        const rules = [];

        for (const rs of this.config.rulesets) {
            if (rs.isBuiltin) {
                if (rs.type === 'GEOIP') {
                    rules.push(`GEOIP,${rs.value},${rs.group}`);
                }
            } else {
                const name = this.getProviderName(rs.source);
                rules.push(`RULE-SET,${name},${rs.group}`);
            }
        }

        rules.push('MATCH,🐟 漏网之鱼');
        return rules;
    }

    generateRuleProviders() {
        const providers = {};

        for (const rs of this.config.rulesets) {
            if (!rs.isBuiltin) {
                const name = this.getProviderName(rs.source);
                providers[name] = {
                    type: 'http',
                    behavior: 'classical',
                    url: rs.source,
                    path: `./ruleset/${name}.yaml`,
                    interval: 86400
                };
            }
        }

        return providers;
    }

    getProviderName(url) {
        const match = url.match(/\/([^\/]+?)(?:\.list|\.yaml|\.txt)?$/);
        if (match) return match[1].replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase();
        return 'provider_' + btoa(url).substring(0, 8).replace(/[=+\/]/g, '_');
    }

    cleanProxy(proxy) {
        const cleaned = {};
        for (const [key, value] of Object.entries(proxy)) {
            if (value !== undefined && value !== null) {
                cleaned[key] = value;
            }
        }
        return cleaned;
    }

    toYaml(obj, indent = 0) {
        const pad = '  '.repeat(indent);
        let yaml = '';

        if (Array.isArray(obj)) {
            for (const item of obj) {
                if (typeof item === 'object' && item !== null) {
                    yaml += `${pad}- `;
                    const inner = this.toYaml(item, 0).trim();
                    yaml += inner.replace(/\n/g, `\n${pad}  `) + '\n';
                } else {
                    yaml += `${pad}- ${this.formatValue(item)}\n`;
                }
            }
        } else if (typeof obj === 'object' && obj !== null) {
            for (const [key, value] of Object.entries(obj)) {
                if (typeof value === 'object' && value !== null) {
                    if (Array.isArray(value) && value.length > 0 && typeof value[0] !== 'object') {
                        yaml += `${pad}${key}: [${value.map(v => this.formatValue(v)).join(', ')}]\n`;
                    } else {
                        yaml += `${pad}${key}:\n${this.toYaml(value, indent + 1)}`;
                    }
                } else {
                    yaml += `${pad}${key}: ${this.formatValue(value)}\n`;
                }
            }
        }

        return yaml;
    }

    formatValue(val) {
        if (typeof val === 'string') {
            if (/[:#\[\]{}|>!&*?]/.test(val) || val.includes('\n') || val === '') {
                return `"${val.replace(/"/g, '\\"')}"`;
            }
            return val;
        }
        if (typeof val === 'boolean') return val ? 'true' : 'false';
        return String(val);
    }
}

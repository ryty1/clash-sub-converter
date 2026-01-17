/**
 * Subscription Parser - CF Workers Version
 */

export class SubParser {
    parse(content) {
        const trimmed = content.trim();

        // Try YAML
        if (trimmed.startsWith('proxies:') || trimmed.includes('\nproxies:')) {
            return this.parseYaml(content);
        }

        // Try Base64
        try {
            const decoded = atob(trimmed);
            if (decoded.includes('://') || decoded.includes('\n')) {
                return this.parseUriList(decoded);
            }
        } catch (e) { }

        // Try URI list
        if (trimmed.includes('://')) {
            return this.parseUriList(trimmed);
        }

        return [];
    }

    parseYaml(content) {
        try {
            const match = content.match(/proxies:\s*\n([\s\S]+?)(?:\nproxy-groups:|$)/);
            if (!match) return [];

            const proxiesSection = match[1];
            const proxies = [];
            const proxyMatches = proxiesSection.matchAll(/^\s*-\s*\{([^}]+)\}/gm);

            for (const m of proxyMatches) {
                try {
                    const proxyStr = `{${m[1]}}`;
                    const proxy = this.parseYamlProxy(proxyStr);
                    if (proxy) proxies.push(proxy);
                } catch (e) { }
            }

            return proxies;
        } catch (e) {
            return [];
        }
    }

    parseYamlProxy(str) {
        const obj = {};
        const pairs = str.slice(1, -1).split(',');
        for (const pair of pairs) {
            const [key, ...vals] = pair.split(':');
            if (key && vals.length) {
                obj[key.trim()] = vals.join(':').trim().replace(/^["']|["']$/g, '');
            }
        }
        return obj.name ? obj : null;
    }

    parseUriList(content) {
        const proxies = [];
        const lines = content.split('\n').filter(l => l.trim());

        for (const line of lines) {
            const proxy = this.parseUri(line.trim());
            if (proxy) proxies.push(proxy);
        }

        return proxies;
    }

    parseUri(uri) {
        if (uri.startsWith('vmess://')) return this.parseVmess(uri);
        if (uri.startsWith('vless://')) return this.parseVless(uri);
        if (uri.startsWith('trojan://')) return this.parseTrojan(uri);
        if (uri.startsWith('ss://')) return this.parseShadowsocks(uri);
        if (uri.startsWith('hysteria2://') || uri.startsWith('hy2://')) return this.parseHysteria2(uri);
        if (uri.startsWith('tuic://')) return this.parseTuic(uri);
        return null;
    }

    parseVmess(uri) {
        try {
            const encoded = uri.replace('vmess://', '');
            const decoded = atob(encoded);
            const config = JSON.parse(decoded);

            const proxy = {
                name: config.ps || config.name || 'VMess',
                type: 'vmess',
                server: config.add || config.server,
                port: parseInt(config.port),
                uuid: config.id || config.uuid,
                alterId: parseInt(config.aid) || 0,
                cipher: config.scy || 'auto',
                tls: config.tls === 'tls',
                'skip-cert-verify': true,
                network: config.net || 'tcp'
            };

            if (config.net === 'ws') {
                proxy['ws-opts'] = {
                    path: config.path || '/',
                    headers: config.host ? { Host: config.host } : {}
                };
            }

            return proxy;
        } catch (e) {
            return null;
        }
    }

    parseVless(uri) {
        try {
            const url = new URL(uri);
            const params = url.searchParams;

            const proxy = {
                name: decodeURIComponent(url.hash.substring(1)) || 'VLESS',
                type: 'vless',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                uuid: url.username,
                tls: params.get('security') === 'tls' || params.get('security') === 'reality',
                'skip-cert-verify': true,
                network: params.get('type') || 'tcp'
            };

            if (proxy.tls) {
                proxy.servername = params.get('sni') || url.hostname;
                if (params.get('security') === 'reality') {
                    proxy['reality-opts'] = {
                        'public-key': params.get('pbk'),
                        'short-id': params.get('sid') || ''
                    };
                }
            }

            if (proxy.network === 'ws') {
                proxy['ws-opts'] = {
                    path: params.get('path') || '/',
                    headers: params.get('host') ? { Host: params.get('host') } : {}
                };
            }

            return proxy;
        } catch (e) {
            return null;
        }
    }

    parseTrojan(uri) {
        try {
            const url = new URL(uri);
            const params = url.searchParams;

            const proxy = {
                name: decodeURIComponent(url.hash.substring(1)) || 'Trojan',
                type: 'trojan',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                sni: params.get('sni') || url.hostname,
                'skip-cert-verify': true,
                network: params.get('type') || 'tcp'
            };

            if (proxy.network === 'ws') {
                proxy['ws-opts'] = {
                    path: params.get('path') || '/',
                    headers: params.get('host') ? { Host: params.get('host') } : {}
                };
            }

            return proxy;
        } catch (e) {
            return null;
        }
    }

    parseShadowsocks(uri) {
        try {
            let content = uri.replace('ss://', '');
            let name = 'Shadowsocks';

            const hashIndex = content.indexOf('#');
            if (hashIndex !== -1) {
                name = decodeURIComponent(content.substring(hashIndex + 1));
                content = content.substring(0, hashIndex);
            }

            if (content.includes('@')) {
                const [authPart, serverPart] = content.split('@');
                let method, password;

                try {
                    const decoded = atob(authPart);
                    [method, password] = decoded.split(':');
                } catch {
                    [method, password] = authPart.split(':');
                }

                const [server, port] = serverPart.split(':');

                return { name, type: 'ss', server, port: parseInt(port), cipher: method, password };
            }

            const decoded = atob(content);
            const atIndex = decoded.lastIndexOf('@');
            const [authPart, serverPart] = [decoded.substring(0, atIndex), decoded.substring(atIndex + 1)];
            const [method, password] = authPart.split(':');
            const colonIndex = serverPart.lastIndexOf(':');
            const server = serverPart.substring(0, colonIndex);
            const port = serverPart.substring(colonIndex + 1);

            return { name, type: 'ss', server, port: parseInt(port), cipher: method, password };
        } catch (e) {
            return null;
        }
    }

    parseHysteria2(uri) {
        try {
            const url = new URL(uri.replace('hy2://', 'hysteria2://'));
            const params = url.searchParams;

            return {
                name: decodeURIComponent(url.hash.substring(1)) || 'Hysteria2',
                type: 'hysteria2',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                password: url.username,
                sni: params.get('sni') || url.hostname,
                'skip-cert-verify': true
            };
        } catch (e) {
            return null;
        }
    }

    parseTuic(uri) {
        try {
            const url = new URL(uri);
            const params = url.searchParams;
            const [uuid, password] = url.username.split(':');

            return {
                name: decodeURIComponent(url.hash.substring(1)) || 'TUIC',
                type: 'tuic',
                server: url.hostname,
                port: parseInt(url.port) || 443,
                uuid: uuid,
                password: password || url.password,
                sni: params.get('sni') || url.hostname,
                'skip-cert-verify': true,
                'congestion-controller': params.get('congestion_control') || 'bbr'
            };
        } catch (e) {
            return null;
        }
    }

    addEmoji(proxy) {
        const name = proxy.name;
        const emojiMap = {
            '🇭🇰': ['港', 'HK', 'Hong Kong'],
            '🇹🇼': ['台', 'TW', 'Taiwan'],
            '🇯🇵': ['日本', 'JP', 'Japan', 'tokyo', 'osaka'],
            '🇰🇷': ['韩国', 'KR', 'Korea', 'seoul'],
            '🇸🇬': ['新加坡', 'SG', 'Singapore'],
            '🇺🇸': ['美国', 'US', 'USA', 'United States', 'Los Angeles', 'Seattle'],
            '🇬🇧': ['英国', 'UK', 'GB', 'United Kingdom', 'London'],
            '🇩🇪': ['德国', 'DE', 'Germany', 'Frankfurt'],
            '🇫🇷': ['法国', 'FR', 'France', 'Paris'],
            '🇳🇱': ['荷兰', 'NL', 'Netherlands', 'Amsterdam'],
            '🇷🇺': ['俄罗斯', 'RU', 'Russia', 'Moscow'],
            '🇨🇦': ['加拿大', 'CA', 'Canada'],
            '🇦🇺': ['澳洲', 'AU', 'Australia', 'Sydney'],
            '🇮🇳': ['印度', 'India', 'Mumbai']
        };

        for (const [emoji, keywords] of Object.entries(emojiMap)) {
            for (const keyword of keywords) {
                if (name.includes(keyword)) {
                    if (!/^[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/.test(name)) {
                        proxy.name = `${emoji} ${name}`;
                    }
                    return proxy;
                }
            }
        }
        return proxy;
    }
}

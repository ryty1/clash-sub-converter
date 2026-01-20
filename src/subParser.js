/**
 * Subscription Parser - CF Workers Version
 */

export class SubParser {
    // UTF-8 safe Base64 decode
    base64DecodeUtf8(str) {
        try {
            const binaryStr = atob(str);
            const bytes = new Uint8Array(binaryStr.length);
            for (let i = 0; i < binaryStr.length; i++) {
                bytes[i] = binaryStr.charCodeAt(i);
            }
            return new TextDecoder('utf-8').decode(bytes);
        } catch (e) {
            return atob(str); // fallback
        }
    }

    parse(content) {
        const trimmed = content.trim();

        // Try YAML
        if (trimmed.startsWith('proxies:') || trimmed.includes('\nproxies:')) {
            return this.parseYaml(content);
        }

        // Try Base64
        try {
            const decoded = this.base64DecodeUtf8(trimmed);
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
                'skip-cert-verify': false,
                network: params.get('type') || 'tcp'
            };

            // 解析 flow (xtls-rprx-vision 等)
            const flow = params.get('flow');
            if (flow) {
                proxy.flow = flow;
            }

            // 解析 client-fingerprint (fp 参数)
            const fingerprint = params.get('fp');
            if (fingerprint) {
                proxy['client-fingerprint'] = fingerprint;
            }

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
                const host = params.get('host') || params.get('sni') || url.hostname;
                proxy['ws-opts'] = {
                    path: params.get('path') || '/',
                    headers: host ? { Host: host } : {}
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
            const urlObj = new URL(uri);
            const params = urlObj.searchParams;
            let content = uri.replace('ss://', '').split('?')[0]; // Handle legacy/partial parsing
            let name = decodeURIComponent(urlObj.hash.substring(1)) || 'Shadowsocks';

            // If URL parsing worked for base, use it; otherwise fallback to manual parsing (for some non-standard formats)
            let method, password, server, port;

            if (content.includes('@')) {
                const [authPart, serverPart] = content.split('@');
                try {
                    const decoded = atob(authPart);
                    [method, password] = decoded.split(':');
                } catch {
                    [method, password] = authPart.split(':');
                }
                const [s, p] = serverPart.split(':');
                server = s;
                port = p;
            } else {
                try {
                    const decoded = atob(content);
                    const atIndex = decoded.lastIndexOf('@');
                    const [authPart, serverPart] = [decoded.substring(0, atIndex), decoded.substring(atIndex + 1)];
                    [method, password] = authPart.split(':');
                    const colonIndex = serverPart.lastIndexOf(':');
                    server = serverPart.substring(0, colonIndex);
                    port = serverPart.substring(colonIndex + 1);
                } catch (e) {
                    return null;
                }
            }

            const proxy = {
                name,
                type: 'ss',
                server,
                port: parseInt(port),
                cipher: method,
                password
            };

            // Parse Plugin - Handle malformed URIs where & is not encoded in plugin params
            let pluginStr = params.get('plugin');

            // Try to extract raw plugin string if standard parsing looks truncated (or just always try to be safe)
            // Match plugin=... until end of string or hash
            const match = uri.match(/[?&]plugin=([^#]+)/);
            if (match) {
                // If the raw match implies the param was NOT properly encoded (contains raw & or ; inside), 
                // we should prefer the raw match to capture the full string.
                // However, valid URIs might have other params. 
                // Given the issue (path truncation), we assume everything after plugin= belongs to plugin 
                // if it looks like v2ray-plugin args.
                const rawPlugin = match[1];
                if (rawPlugin.includes('path=') || rawPlugin.includes('obfs-host=')) {
                    pluginStr = rawPlugin;
                }
            }

            if (pluginStr) {
                const pluginParts = decodeURIComponent(pluginStr).split(';');
                proxy.plugin = pluginParts[0];
                proxy['plugin-opts'] = {};

                for (let i = 1; i < pluginParts.length; i++) {
                    const part = pluginParts[i];
                    const equalsIndex = part.indexOf('=');
                    if (equalsIndex !== -1) {
                        const key = part.substring(0, equalsIndex);
                        let val = part.substring(equalsIndex + 1);
                        try {
                            if (val.includes('%')) {
                                val = decodeURIComponent(val);
                            }
                        } catch (e) { }
                        proxy['plugin-opts'][key] = val;
                    } else {
                        proxy['plugin-opts'][part] = true;
                    }
                }

                // Normalization for v2ray-plugin
                if (proxy.plugin === 'v2ray-plugin' || proxy.plugin === 'obfs-local') {
                    if (proxy['plugin-opts'].tls === 'true' || proxy['plugin-opts'].tls === true) {
                        proxy['plugin-opts'].tls = true;
                        // Map skip-cert-verify to allowInsecure if present in proxy or opts
                        if (proxy['skip-cert-verify'] === true || proxy['plugin-opts']['skip-cert-verify'] === 'true') {
                            proxy['plugin-opts'].allowInsecure = true;
                        }
                    }

                    // Explicitly set mux to false
                    proxy['plugin-opts'].mux = false;

                    // Ensure 'peer' is set if 'host' or 'sni' is present
                    // 'peer' is often used as SNI in v2ray-plugin
                    if (proxy['plugin-opts'].host) {
                        proxy['plugin-opts'].peer = proxy['plugin-opts'].host;
                    } else if (params.get('sni')) {
                        proxy['plugin-opts'].peer = params.get('sni');
                        proxy['plugin-opts'].host = params.get('sni');
                    }
                }
            }

            // Client Fingerprint
            const fingerprint = params.get('fingerprint') || params.get('client-fingerprint');
            if (fingerprint) {
                proxy['client-fingerprint'] = fingerprint;
            }

            return proxy;
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
            '🇮🇳': ['印度', 'India', 'Mumbai'],
            '🇲🇽': ['墨西哥', 'Mexico'],
            '🇦🇪': ['阿联酋', 'UAE', 'United Arab Emirates', '迪拜', 'Dubai'],
            '🇫🇮': ['芬兰', 'Finland', 'Helsinki'],
            '🇸🇪': ['瑞典', 'Sweden', 'Stockholm'],
            '🇨🇭': ['瑞士', 'Switzerland', 'Zurich'],
            '🇹🇷': ['土耳其', 'Turkey', 'Istanbul'],
            '🇧🇷': ['巴西', 'Brazil', 'Sao Paulo'],
            '🇦🇷': ['阿根廷', 'Argentina'],
            '🇨🇱': ['智利', 'Chile'],
            '🇮🇹': ['意大利', 'Italy', 'Milan', 'Rome'],
            '🇺🇦': ['乌克兰', 'Ukraine'],
            '🇵🇭': ['菲律宾', 'Philippines'],
            '🇻🇳': ['越南', 'Vietnam'],
            '🇹🇭': ['泰国', 'Thailand', 'Bangkok'],
            '🇲🇾': ['马来西亚', 'Malaysia', 'Kuala Lumpur'],
            '🇮🇩': ['印尼', 'Indonesia', 'Jakarta'],
            '🇪🇬': ['埃及', 'Egypt'],
            '🇿🇦': ['南非', 'South Africa', 'Johannesburg']
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

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
            '☁️': ['snippets', 'Snippets', 'sni', 'Sni', 'snip', 'Snip'],
            '🇭🇰': ['香港', 'HK', 'hk', 'Hong Kong', 'HongKong', 'hongkong', 'HKG'],
            '🇲🇴': ['澳门', 'MO', 'Macau', 'macao'],
            '🇹🇼': ['台湾', '新北', '彰化', 'TW', 'Taiwan', 'taipei'],
            '🇯🇵': ['日本', '川日', '东京', '大阪', '泉日', '埼玉', '沪日', '深日', '[^-]日', 'JP', 'Japan', 'tokyo', 'osaka'],
            '🇰🇷': ['韩国', '韩', 'KR', 'Korea', 'KOR', '首尔', 'seoul', '春川'],
            '🇲🇳': ['蒙古', 'Mongolia', '乌兰巴托'],
            '🇸🇬': ['新加坡', '坡', '狮城', 'SG', 'Singapore'],
            '🇲🇾': ['马来西亚', '马来', 'MY', 'Malaysia', '吉隆坡'],
            '🇹🇭': ['泰国', 'TH', 'Thailand', '曼谷'],
            '🇻🇳': ['越南', 'VN', 'Vietnam', '胡志明', '河内'],
            '🇵🇭': ['菲律宾', 'PH', 'Philippines', '马尼拉'],
            '🇮🇩': ['印度尼西亚', '印尼', 'ID', 'Indonesia', '雅加达'],
            '🇰🇭': ['柬埔寨', 'Cambodia', '金边'],
            '🇲🇲': ['缅甸', 'Myanmar', '仰光'],
            '🇱🇦': ['老挝', 'Laos', '万象'],
            '🇧🇳': ['文莱', 'Brunei'],
            '🇹🇱': ['东帝汶', 'Timor-Leste'],
            '🇮🇳': ['印度', 'India', '孟买', '新德里', 'Mumbai', 'Delhi'],
            '🇵🇰': ['巴基斯坦', 'Pakistan', '卡拉奇', '伊斯兰堡'],
            '🇧🇩': ['孟加拉', 'Bangladesh', '达卡'],
            '🇳🇵': ['尼泊尔', 'Nepal', '加德满都'],
            '🇱🇰': ['斯里兰卡', 'Sri Lanka', '科伦坡'],
            '🇧🇹': ['不丹', 'Bhutan'],
            '🇲🇻': ['马尔代夫', 'Maldives', '马累'],
            '🇦🇫': ['阿富汗', 'Afghanistan', '喀布尔'],
            '🇰🇿': ['哈萨克斯坦', '哈萨克', 'Kazakhstan', '阿拉木图'],
            '🇺🇿': ['乌兹别克斯坦', '乌兹别克', 'Uzbekistan', '塔什干'],
            '🇹🇲': ['土库曼斯坦', '土库曼', 'Turkmenistan'],
            '🇹🇯': ['塔吉克斯坦', '塔吉克', 'Tajikistan'],
            '🇰🇬': ['吉尔吉斯斯坦', '吉尔吉斯', 'Kyrgyzstan'],
            '🇦🇿': ['阿塞拜疆', 'Azerbaijan', '巴库'],
            '🇦🇲': ['亚美尼亚', 'Armenia', '埃里温'],
            '🇬🇪': ['格鲁吉亚', 'Georgia', '第比利斯'],
            '🇦🇪': ['阿联酋', 'United Arab Emirates', '迪拜', 'Dubai', '阿布扎比'],
            '🇸🇦': ['沙特', 'Saudi Arabia', '沙特阿拉伯', '利雅得'],
            '🇮🇱': ['以色列', 'Israel', '特拉维夫'],
            '🇹🇷': ['土耳其', 'Turkey', '伊斯坦布尔', '安卡拉'],
            '🇮🇷': ['伊朗', 'Iran', '德黑兰'],
            '🇮🇶': ['伊拉克', 'Iraq', '巴格达'],
            '🇶🇦': ['卡塔尔', 'Qatar', '多哈'],
            '🇰🇼': ['科威特', 'Kuwait'],
            '🇴🇲': ['阿曼', 'Oman', '马斯喀特'],
            '🇧🇭': ['巴林', 'Bahrain', '麦纳麦'],
            '🇯🇴': ['约旦', 'Jordan', '安曼'],
            '🇱🇧': ['黎巴嫩', 'Lebanon', '贝鲁特'],
            '🇸🇾': ['叙利亚', 'Syria', '大马士革'],
            '🇾🇪': ['也门', 'Yemen', '萨那'],
            '🇵🇸': ['巴勒斯坦', 'Palestine'],
            '🇺🇸': ['美国', '美', '波特兰', '达拉斯', '俄勒冈', '凤凰城', '费利蒙', '硅谷', '拉斯维加斯', '洛杉矶', '圣何塞', '圣克拉拉', '西雅图', '芝加哥', 'US', 'USA', 'United States', 'ATL', 'BUF', 'DFW', 'EWR', 'IAD', 'LAX', 'MCI', 'MIA', 'ORD', 'PHX', 'PDX', 'SEA', 'SJC'],
            '🇨🇦': ['加拿大', 'CA', 'Canada', '多伦多', '温哥华', '蒙特利尔'],
            '🇲🇽': ['墨西哥', 'Mexico', '墨城'],
            '🇵🇦': ['巴拿马', 'Panama'],
            '🇨🇷': ['哥斯达黎加', 'Costa Rica'],
            '🇬🇹': ['危地马拉', 'Guatemala'],
            '🇭🇳': ['洪都拉斯', 'Honduras'],
            '🇳🇮': ['尼加拉瓜', 'Nicaragua'],
            '🇸🇻': ['萨尔瓦多', 'El Salvador'],
            '🇧🇿': ['伯利兹', 'Belize'],
            '🇨🇺': ['古巴', 'Cuba', '哈瓦那'],
            '🇩🇴': ['多米尼加', 'Dominican', '圣多明各'],
            '🇯🇲': ['牙买加', 'Jamaica', '金斯敦'],
            '🇭🇹': ['海地', 'Haiti'],
            '🇧🇸': ['巴哈马', 'Bahamas'],
            '🇧🇧': ['巴巴多斯', 'Barbados'],
            '🇹🇹': ['特立尼达', 'Trinidad'],
            '🇵🇷': ['波多黎各', 'Puerto Rico'],
            '🇧🇷': ['巴西', 'Brazil', '圣保罗', '里约'],
            '🇦🇷': ['阿根廷', 'Argentina', '布宜诺斯艾利斯'],
            '🇨🇱': ['智利', 'Chile', '圣地亚哥'],
            '🇨🇴': ['哥伦比亚', 'Colombia', '波哥大'],
            '🇵🇪': ['秘鲁', 'Peru', '利马'],
            '🇻🇪': ['委内瑞拉', 'Venezuela', '加拉加斯'],
            '🇪🇨': ['厄瓜多尔', 'Ecuador', '基多'],
            '🇺🇾': ['乌拉圭', 'Uruguay', '蒙得维的亚'],
            '🇧🇴': ['玻利维亚', 'Bolivia', '拉巴斯'],
            '🇵🇾': ['巴拉圭', 'Paraguay', '亚松森'],
            '🇬🇾': ['圭亚那', 'Guyana'],
            '🇸🇷': ['苏里南', 'Suriname'],
            '🇬🇫': ['法属圭亚那', 'French Guiana'],
            '🇬🇧': ['英国', 'UK', 'GB', 'United Kingdom', 'Britain', '伦敦', 'London', '曼彻斯特'],
            '🇩🇪': ['德国', 'DE', 'Germany', '法兰克福', '柏林', '慕尼黑', 'Frankfurt'],
            '🇫🇷': ['法国', 'FR', 'France', '巴黎', 'Paris', '马赛'],
            '🇳🇱': ['荷兰', 'NL', 'Netherlands', '阿姆斯特丹', 'Amsterdam'],
            '🇧🇪': ['比利时', 'Belgium', '布鲁塞尔'],
            '🇱🇺': ['卢森堡', 'Luxembourg'],
            '🇨🇭': ['瑞士', 'Switzerland', '苏黎世', '日内瓦'],
            '🇦🇹': ['奥地利', 'Austria', '维也纳'],
            '🇮🇪': ['爱尔兰', 'Ireland', '都柏林'],
            '🇲🇨': ['摩纳哥', 'Monaco'],
            '🇱🇮': ['列支敦士登', 'Liechtenstein'],
            '🇦🇩': ['安道尔', 'Andorra'],
            '🇸🇪': ['瑞典', 'Sweden', '斯德哥尔摩'],
            '🇳🇴': ['挪威', 'Norway', '奥斯陆'],
            '🇫🇮': ['芬兰', 'Finland', '赫尔辛基'],
            '🇩🇰': ['丹麦', 'Denmark', '哥本哈根'],
            '🇮🇸': ['冰岛', 'Iceland', '雷克雅未克'],
            '🇫🇴': ['法罗群岛', 'Faroe'],
            '🇬🇱': ['格陵兰', 'Greenland'],
            '🇮🇹': ['意大利', 'Italy', '米兰', '罗马', '都灵'],
            '🇪🇸': ['西班牙', 'Spain', '马德里', '巴塞罗那'],
            '🇵🇹': ['葡萄牙', 'Portugal', '里斯本'],
            '🇬🇷': ['希腊', 'Greece', '雅典'],
            '🇨🇾': ['塞浦路斯', 'Cyprus', '尼科西亚'],
            '🇲🇹': ['马耳他', 'Malta', '瓦莱塔'],
            '🇸🇲': ['圣马力诺', 'San Marino'],
            '🇻🇦': ['梵蒂冈', 'Vatican'],
            '🇦🇱': ['阿尔巴尼亚', 'Albania', '地拉那'],
            '🇲🇰': ['北马其顿', '马其顿', 'North Macedonia'],
            '🇽🇰': ['科索沃', 'Kosovo'],
            '🇲🇪': ['黑山', 'Montenegro'],
            '🇧🇦': ['波黑', '波斯尼亚', 'Bosnia'],
            '🇷🇺': ['俄罗斯', '俄', 'RU', 'Russia', '莫斯科', '圣彼得堡', 'Moscow'],
            '🇺🇦': ['乌克兰', 'Ukraine', '基辅'],
            '🇧🇾': ['白俄罗斯', 'Belarus', '明斯克'],
            '🇵🇱': ['波兰', 'Poland', '华沙'],
            '🇨🇿': ['捷克', 'Czech', '布拉格'],
            '🇸🇰': ['斯洛伐克', 'Slovakia', '布拉迪斯拉发'],
            '🇭🇺': ['匈牙利', 'Hungary', '布达佩斯'],
            '🇷🇴': ['罗马尼亚', 'Romania', '布加勒斯特'],
            '🇧🇬': ['保加利亚', 'Bulgaria', '索非亚'],
            '🇲🇩': ['摩尔多瓦', 'Moldova', '基希讷乌'],
            '🇱🇻': ['拉脱维亚', 'Latvia', '里加'],
            '🇱🇹': ['立陶宛', 'Lithuania', '维尔纽斯'],
            '🇪🇪': ['爱沙尼亚', 'Estonia', '塔林'],
            '🇸🇮': ['斯洛文尼亚', 'Slovenia', '卢布尔雅那'],
            '🇭🇷': ['克罗地亚', 'Croatia', '萨格勒布'],
            '🇷🇸': ['塞尔维亚', 'Serbia', '贝尔格莱德'],
            '🇦🇺': ['澳洲', '澳大利亚', 'AU', 'Australia', '悉尼', '墨尔本', 'Sydney', 'Melbourne'],
            '🇳🇿': ['新西兰', 'New Zealand', '奥克兰'],
            '🇫🇯': ['斐济', 'Fiji', '苏瓦'],
            '🇵🇬': ['巴布亚新几内亚', '巴新', 'Papua New Guinea'],
            '🇼🇸': ['萨摩亚', 'Samoa'],
            '🇹🇴': ['汤加', 'Tonga'],
            '🇻🇺': ['瓦努阿图', 'Vanuatu'],
            '🇸🇧': ['所罗门群岛', 'Solomon'],
            '🇳🇨': ['新喀里多尼亚', 'New Caledonia'],
            '🇵🇫': ['法属波利尼西亚', 'French Polynesia', '大溪地'],
            '🇬🇺': ['关岛', 'Guam'],
            '🇪🇬': ['埃及', 'Egypt', '开罗'],
            '🇱🇾': ['利比亚', 'Libya', '的黎波里'],
            '🇹🇳': ['突尼斯', 'Tunisia', '突尼斯城'],
            '🇩🇿': ['阿尔及利亚', 'Algeria', '阿尔及尔'],
            '🇲🇦': ['摩洛哥', 'Morocco', '卡萨布兰卡'],
            '🇸🇩': ['苏丹', 'Sudan', '喀土穆'],
            '🇳🇬': ['尼日利亚', 'Nigeria', '拉各斯'],
            '🇬🇭': ['加纳', 'Ghana', '阿克拉'],
            '🇸🇳': ['塞内加尔', 'Senegal', '达喀尔'],
            '🇨🇮': ['科特迪瓦', '象牙海岸', 'Ivory Coast', 'Cote'],
            '🇲🇱': ['马里', 'Mali', '巴马科'],
            '🇧🇫': ['布基纳法索', 'Burkina Faso'],
            '🇳🇪': ['尼日尔', 'Niger'],
            '🇬🇳': ['几内亚', 'Guinea'],
            '🇹🇬': ['多哥', 'Togo'],
            '🇧🇯': ['贝宁', 'Benin'],
            '🇱🇷': ['利比里亚', 'Liberia'],
            '🇸🇱': ['塞拉利昂', 'Sierra Leone'],
            '🇲🇷': ['毛里塔尼亚', 'Mauritania'],
            '🇬🇲': ['冈比亚', 'Gambia'],
            '🇨🇻': ['佛得角', 'Cape Verde'],
            '🇨🇲': ['喀麦隆', 'Cameroon', '雅温得'],
            '🇨🇩': ['刚果民主共和国', '刚果金', 'DR Congo'],
            '🇨🇬': ['刚果共和国', '刚果布', 'Congo'],
            '🇨🇫': ['中非共和国', '中非', 'Central African'],
            '🇹🇩': ['乍得', 'Chad'],
            '🇬🇦': ['加蓬', 'Gabon'],
            '🇬🇶': ['赤道几内亚', 'Equatorial Guinea'],
            '🇰🇪': ['肯尼亚', 'Kenya', '内罗毕'],
            '🇹🇿': ['坦桑尼亚', 'Tanzania', '达累斯萨拉姆'],
            '🇺🇬': ['乌干达', 'Uganda', '坎帕拉'],
            '🇷🇼': ['卢旺达', 'Rwanda', '基加利'],
            '🇧🇮': ['布隆迪', 'Burundi'],
            '🇪🇹': ['埃塞俄比亚', 'Ethiopia', '亚的斯亚贝巴'],
            '🇪🇷': ['厄立特里亚', 'Eritrea'],
            '🇩🇯': ['吉布提', 'Djibouti'],
            '🇸🇴': ['索马里', 'Somalia'],
            '🇲🇬': ['马达加斯加', 'Madagascar'],
            '🇲🇺': ['毛里求斯', 'Mauritius'],
            '🇸🇨': ['塞舌尔', 'Seychelles'],
            '🇰🇲': ['科摩罗', 'Comoros'],
            '🇷🇪': ['留尼汪', 'Reunion'],
            '🇿🇦': ['南非', 'South Africa', '约翰内斯堡', '开普敦'],
            '🇿🇼': ['津巴布韦', 'Zimbabwe', '哈拉雷'],
            '🇿🇲': ['赞比亚', 'Zambia', '卢萨卡'],
            '🇲🇼': ['马拉维', 'Malawi'],
            '🇲🇿': ['莫桑比克', 'Mozambique', '马普托'],
            '🇧🇼': ['博茨瓦纳', 'Botswana'],
            '🇳🇦': ['纳米比亚', 'Namibia', '温得和克'],
            '🇦🇴': ['安哥拉', 'Angola', '罗安达'],
            '🇸🇿': ['斯威士兰', 'Eswatini', 'Swaziland'],
            '🇱🇸': ['莱索托', 'Lesotho']
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

/**
 * Clash Subscription Converter - Cloudflare Workers Version
 */

import { CONFIG } from './config.js';
import { SubParser } from './subParser.js';
import { ClashGenerator } from './clashGenerator.js';
import { HTML_TEMPLATE } from './frontend.js';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        try {
            // Route handling
            if (path === '/' || path === '/index.html') {
                return new Response(HTML_TEMPLATE, {
                    headers: { 'Content-Type': 'text/html; charset=utf-8', ...corsHeaders }
                });
            }

            if (path === '/sub') {
                return await handleSubscription(url, corsHeaders);
            }

            if (path === '/api/info') {
                return Response.json({
                    name: 'Clash Subscription Converter',
                    version: '1.0.0-cf',
                    platform: 'Cloudflare Workers',
                    features: ['VMess', 'VLESS', 'Trojan', 'SS', 'Hysteria', 'TUIC'],
                    proxyGroups: CONFIG.proxyGroups.length,
                    rulesets: CONFIG.rulesets.length
                }, { headers: corsHeaders });
            }

            if (path === '/api/groups') {
                return Response.json(
                    CONFIG.proxyGroups.map(g => ({ name: g.name, type: g.type })),
                    { headers: corsHeaders }
                );
            }

            if (path === '/health') {
                return Response.json({ status: 'ok', timestamp: Date.now() }, { headers: corsHeaders });
            }

            return new Response('Not Found', { status: 404 });

        } catch (e) {
            return Response.json({ error: e.message }, { status: 500, headers: corsHeaders });
        }
    }
};

async function handleSubscription(url, corsHeaders) {
    const params = url.searchParams;
    const subUrl = params.get('url');

    if (!subUrl) {
        return Response.json({ error: 'Missing url parameter' }, { status: 400, headers: corsHeaders });
    }

    // Fetch subscriptions with recursive parsing
    const subscriptionUrls = decodeURIComponent(subUrl).split('|');
    const subParser = new SubParser();
    let allProxies = [];

    // Helper function to fetch and parse content recursively
    async function fetchAndParse(urlToFetch, depth = 0) {
        if (depth > 3) return []; // Max recursion depth to prevent infinite loops

        try {
            const response = await fetch(urlToFetch.trim(), {
                headers: { 'User-Agent': 'ClashSubConverter/1.0' }
            });
            if (!response.ok) return [];

            const content = await response.text();
            const trimmed = content.trim();

            // Check if content is already parseable as proxies
            const parsedProxies = subParser.parse(content);
            if (parsedProxies.length > 0) {
                return parsedProxies;
            }

            // Check for nested subscription URLs (https:// links in content)
            const lines = trimmed.split('\n').filter(l => l.trim());
            const nestedProxies = [];

            for (const line of lines) {
                const trimmedLine = line.trim();
                if (trimmedLine.startsWith('https://') || trimmedLine.startsWith('http://')) {
                    // Recursively fetch nested subscription
                    const nested = await fetchAndParse(trimmedLine, depth + 1);
                    nestedProxies.push(...nested);
                }
            }

            if (nestedProxies.length > 0) {
                return nestedProxies;
            }

            return [];
        } catch (e) {
            console.error(`Failed to fetch: ${urlToFetch}`, e);
            return [];
        }
    }

    // Process all subscription URLs in order
    for (const u of subscriptionUrls) {
        const proxies = await fetchAndParse(u.trim());
        allProxies = allProxies.concat(proxies);
    }

    if (allProxies.length === 0) {
        return Response.json({ error: 'No valid proxies found' }, { status: 400, headers: corsHeaders });
    }

    // Apply filters
    const exclude = params.get('exclude');
    const include = params.get('include');
    const emoji = params.get('emoji') !== 'false';
    const target = params.get('target') || 'clash';

    if (exclude) {
        const regex = new RegExp(decodeURIComponent(exclude), 'i');
        allProxies = allProxies.filter(p => !regex.test(p.name));
    }

    if (include) {
        const regex = new RegExp(decodeURIComponent(include), 'i');
        allProxies = allProxies.filter(p => regex.test(p.name));
    }

    if (emoji) {
        allProxies = allProxies.map(p => subParser.addEmoji(p));
    }

    // Generate config
    const generator = new ClashGenerator(CONFIG);
    const output = await generator.generate(allProxies, target === 'clash.meta');

    return new Response(output, {
        headers: {
            'Content-Type': 'text/yaml; charset=utf-8',
            'Content-Disposition': 'attachment; filename="clash.yaml"',
            ...corsHeaders
        }
    });
}

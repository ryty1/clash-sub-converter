/**
 * Cloudflare Pages Functions - Catch-all handler
 * This file enables deployment on CF Pages
 */

import { CONFIG } from '../src/config.js';
import { SubParser } from '../src/subParser.js';
import { ClashGenerator } from '../src/clashGenerator.js';
import { HTML_TEMPLATE } from '../src/frontend.js';

export async function onRequest(context) {
    const { request } = context;
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
                platform: 'Cloudflare Pages',
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

async function handleSubscription(url, corsHeaders) {
    const params = url.searchParams;
    const subUrl = params.get('url');

    if (!subUrl) {
        return Response.json({ error: 'Missing url parameter' }, { status: 400, headers: corsHeaders });
    }

    // Fetch subscriptions
    const subscriptionUrls = decodeURIComponent(subUrl).split('|');
    const subParser = new SubParser();
    let allProxies = [];

    for (const u of subscriptionUrls) {
        try {
            const response = await fetch(u, {
                headers: { 'User-Agent': 'ClashSubConverter/1.0' }
            });
            if (response.ok) {
                const content = await response.text();
                const proxies = subParser.parse(content);
                allProxies = allProxies.concat(proxies);
            }
        } catch (e) {
            console.error(`Failed to fetch: ${u}`, e);
        }
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

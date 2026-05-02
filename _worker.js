import { connect } from 'cloudflare:sockets';

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');
        const userAgent = request.headers.get('User-Agent')?.toLowerCase() || '';

        // --- 1. 配置读取 (优先从环境变量读取，匹配你的控制台设置) ---
        const ADMIN_PASS = env.ADMIN_PASS || 'admin888'; 
        const PASSWORD = env.UUID || '487f070f-2aa2-45af-aacc-cc0371a4686b'; 
        const SUB_PATH = env.SUB_PATH || '/';

        // 从 KV 获取动态参数 (如果 KV 为空则使用默认值)
        const PROXY_IP = await env.CONFIG_KV?.get('PROXY_IP') || '141.101.115.51';
        const BYPASS_LIST = await env.CONFIG_KV?.get('BYPASS_LIST') || '';
        const TROJAN_HASH = await env.CONFIG_KV?.get('TROJAN_HASH') || '530d95c256247c473111f185db2d6e35187e1f41d08dcd370e0f31c8';

        // --- 2. 自动生成订阅 (解决解析失败问题) ---
        if (url.pathname === SUB_PATH && !upgradeHeader && !url.pathname.startsWith('/api/')) {
            const isClient = userAgent.includes('clash') || userAgent.includes('shadowrocket') || userAgent.includes('v2ray') || url.searchParams.has('sub');
            if (isClient) {
                const subLink = `trojan://${PASSWORD}@${url.host}:443?encryption=none&security=tls&sni=${url.host}&type=ws&host=${url.host}&path=${encodeURIComponent(SUB_PATH)}#EdgePulse`;
                return new Response(btoa(subLink), { headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
            }
        }

        // --- 3. 管理 API (带完整保存逻辑) ---
        if (url.pathname.startsWith('/api/')) {
            if (request.headers.get('Authorization') !== ADMIN_PASS) {
                return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
            }

            if (url.pathname === '/api/config') {
                if (request.method === 'GET') {
                    return new Response(JSON.stringify({ PROXY_IP, PASSWORD, BYPASS_LIST, SUB_PATH }), {
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
                if (request.method === 'POST') {
                    const data = await request.json();
                    if (data.PROXY_IP) await env.CONFIG_KV.put('PROXY_IP', data.PROXY_IP);
                    if (data.BYPASS_LIST) await env.CONFIG_KV.put('BYPASS_LIST', data.BYPASS_LIST);
                    if (data.TROJAN_HASH) await env.CONFIG_KV.put('TROJAN_HASH', data.TROJAN_HASH);
                    return new Response('OK');
                }
            }
            if (url.pathname === '/api/ping') return new Response('pong');
        }

        // --- 4. Trojan 协议处理 (支持 0-RTT 修复) ---
        if (upgradeHeader === 'websocket' && url.pathname === SUB_PATH) {
            return await handleTrojanWS(request, TROJAN_HASH, PROXY_IP, BYPASS_LIST);
        }

        // --- 5. 静态资源回退 ---
        return await env.ASSETS.fetch(request);
    }
};

async function handleTrojanWS(request, validHash, proxyIp, bypassList) {
    const [client, server] = new WebSocketPair();
    server.accept();
    let earlyData = new Uint8Array(0);
    const edHeader = request.headers.get('Sec-WebSocket-Protocol');
    if (edHeader && edHeader.length > 8) {
        try {
            const b64 = edHeader.replace(/-/g, '+').replace(/_/g, '/');
            earlyData = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
        } catch (e) {}
    }
    processStream(server, earlyData, validHash, proxyIp, bypassList).catch(() => server.close());
    const resHeaders = new Headers();
    if (edHeader) resHeaders.set('Sec-WebSocket-Protocol', edHeader);
    return new Response(null, { status: 101, webSocket: client, headers: resHeaders });
}

async function processStream(server, earlyData, validHash, proxyIp, bypassList) {
    let firstChunk = earlyData;
    if (firstChunk.byteLength === 0) {
        const reader = server.readable.getReader();
        const { value, done } = await reader.read();
        if (done) return;
        firstChunk = value;
        reader.releaseLock();
    }
    if (firstChunk.byteLength < 58) return server.close();
    const clientHash = new TextDecoder().decode(firstChunk.slice(0, 56));
    if (clientHash !== validHash) return server.close();
    let offset = 58;
    const atyp = firstChunk[offset + 1];
    offset += 2;
    let address = '';
    if (atyp === 1) { address = firstChunk.slice(offset, offset + 4).join('.'); offset += 4; }
    else if (atyp === 3) {
        const len = firstChunk[offset++];
        address = new TextDecoder().decode(firstChunk.slice(offset, offset + len));
        offset += len;
    }
    const port = (firstChunk[offset] << 8) | firstChunk[offset + 1];
    offset += 4;
    let target = proxyIp;
    if (bypassList && address) {
        const isBypass = bypassList.split('\n').some(rule => rule.trim() && address.includes(rule.trim().replace('*', '')));
        if (isBypass) target = address;
    }
    const remoteSocket = connect({ hostname: target, port: port }, { keepAlive: true });
    const writer = remoteSocket.writable.getWriter();
    await writer.write(firstChunk.slice(offset));
    writer.releaseLock();
    remoteSocket.readable.pipeTo(server.writable);
    server.readable.pipeTo(remoteSocket.writable);
}

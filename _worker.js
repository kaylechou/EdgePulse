import { connect } from 'cloudflare:sockets';

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');

        // --- 读取配置 ---
        const ADMIN_PASS = await env.CONFIG_KV?.get('ADMIN_PASS') || 'admin888';
        const PASSWORD = await env.CONFIG_KV?.get('PASSWORD') || '487f070f-2aa2-45af-aacc-cc0371a4686b';
        const TROJAN_HASH = await env.CONFIG_KV?.get('TROJAN_HASH') || '530d95c256247c473111f185db2d6e35187e1f41d08dcd370e0f31c8';
        const PROXY_IP = await env.CONFIG_KV?.get('PROXY_IP') || '104.17.105.226';
        const BYPASS_LIST = await env.CONFIG_KV?.get('BYPASS_LIST') || '';

        // --- API 管理接口 ---
        if (url.pathname.startsWith('/api/')) {
            if (request.headers.get('Authorization') !== ADMIN_PASS) return new Response('Unauthorized', { status: 401 });

            if (url.pathname === '/api/config') {
                if (request.method === 'GET') return new Response(JSON.stringify({ PROXY_IP, PASSWORD, BYPASS_LIST }));
                if (request.method === 'POST') {
                    const data = await request.json();
                    await env.CONFIG_KV.put('PROXY_IP', data.PROXY_IP);
                    await env.CONFIG_KV.put('PASSWORD', data.PASSWORD);
                    await env.CONFIG_KV.put('TROJAN_HASH', data.TROJAN_HASH);
                    await env.CONFIG_KV.put('BYPASS_LIST', data.BYPASS_LIST);
                    return new Response('OK');
                }
            }
            if (url.pathname === '/api/ping') return new Response('pong');
        }

        // --- Trojan 协议核心 (支持路径 /) ---
        if (upgradeHeader === 'websocket') {
            return await handleTrojanWS(request, TROJAN_HASH, PROXY_IP, BYPASS_LIST);
        }

        // --- 静态页面返回 ---
        return await env.ASSETS.fetch(request);
    }
};

async function handleTrojanWS(request, validHash, proxyIp, bypassList) {
    const [client, server] = new WebSocketPair();
    server.accept();

    // 提取 Early Data (0-RTT)
    let earlyData = new Uint8Array(0);
    const edHeader = request.headers.get('Sec-WebSocket-Protocol');
    if (edHeader) {
        const b64 = edHeader.replace(/-/g, '+').replace(/_/g, '/');
        earlyData = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    }

    processStream(server, earlyData, validHash, proxyIp, bypassList).catch(() => server.close());

    return new Response(null, { 
        status: 101, 
        webSocket: client, 
        headers: edHeader ? { 'Sec-WebSocket-Protocol': edHeader } : {} 
    });
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

    // 校验哈希
    const clientHash = new TextDecoder().decode(firstChunk.slice(0, 56));
    if (clientHash !== validHash) return server.close();

    // 解析目标地址
    let offset = 58;
    const atyp = firstChunk[offset + 1];
    offset += 2;
    let address = '';
    if (atyp === 1) {
        address = firstChunk.slice(offset, offset + 4).join('.');
        offset += 4;
    } else if (atyp === 3) {
        const len = firstChunk[offset++];
        address = new TextDecoder().decode(firstChunk.slice(offset, offset + len));
        offset += len;
    }

    const port = (firstChunk[offset] << 8) | firstChunk[offset + 1];
    offset += 4; // 跳过端口和末尾 CRLF

    // --- 分流判定 ---
    let finalTarget = proxyIp;
    if (bypassList) {
        const rules = bypassList.split('\n').filter(r => r.trim());
        const isBypass = rules.some(rule => {
            const regex = new RegExp('^' + rule.trim().replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
            return regex.test(address);
        });
        if (isBypass) finalTarget = address;
    }

    // 建立连接并转发
    const remoteSocket = connect({ hostname: finalTarget, port: port }, { keepAlive: true });
    const writer = remoteSocket.writable.getWriter();
    await writer.write(firstChunk.slice(offset));
    writer.releaseLock();

    // 硬件级全双工透传
    remoteSocket.readable.pipeTo(server.writable);
    server.readable.pipeTo(remoteSocket.writable);
}

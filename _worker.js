import { connect } from 'cloudflare:sockets';

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const upgradeHeader = request.headers.get('Upgrade');

        // --- 1. 配置初始化 (优先读取环境变量，其次读取 KV) ---
        const ADMIN_PASS = env.ADMIN_PASS || await env.CONFIG_KV?.get('ADMIN_PASS') || 'admin888';
        const PASSWORD = await env.CONFIG_KV?.get('PASSWORD') || '487f070f-2aa2-45af-aacc-cc0371a4686b';
        const TROJAN_HASH = await env.CONFIG_KV?.get('TROJAN_HASH') || '530d95c256247c473111f185db2d6e35187e1f41d08dcd370e0f31c8';
        const PROXY_IP = await env.CONFIG_KV?.get('PROXY_IP') || '104.17.105.226';
        const BYPASS_LIST = await env.CONFIG_KV?.get('BYPASS_LIST') || '';
        const SUB_PATH = await env.CONFIG_KV?.get('SUB_PATH') || '/';

        // --- 2. 管理 API 接口 ---
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
                    if (data.PASSWORD) await env.CONFIG_KV.put('PASSWORD', data.PASSWORD);
                    if (data.TROJAN_HASH) await env.CONFIG_KV.put('TROJAN_HASH', data.TROJAN_HASH);
                    if (data.PROXY_IP) await env.CONFIG_KV.put('PROXY_IP', data.PROXY_IP);
                    if (data.BYPASS_LIST) await env.CONFIG_KV.put('BYPASS_LIST', data.BYPASS_LIST);
                    if (data.SUB_PATH) await env.CONFIG_KV.put('SUB_PATH', data.SUB_PATH);
                    return new Response('OK');
                }
            }
            if (url.pathname === '/api/ping') return new Response('pong');
        }

        // --- 3. Trojan 协议处理 (支持 WebSocket 0-RTT) ---
        if (upgradeHeader === 'websocket' && url.pathname === SUB_PATH) {
            return await handleTrojanWS(request, TROJAN_HASH, PROXY_IP, BYPASS_LIST);
        }

        // --- 4. 静态资源回退 (防止 404) ---
        try {
            return await env.ASSETS.fetch(request);
        } catch (e) {
            return new Response('Not Found', { status: 404 });
        }
    }
};

async function handleTrojanWS(request, validHash, proxyIp, bypassList) {
    const [client, server] = new WebSocketPair();
    server.accept();

    // 0-RTT Early Data 提取
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

    if (firstChunk.byteLength < 58) return server.close();
    const clientHash = new TextDecoder().decode(firstChunk.slice(0, 56));
    if (clientHash !== validHash) return server.close();

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
    offset += 4;

    // 分流逻辑判定
    let target = proxyIp;
    if (bypassList) {
        const rules = bypassList.split('\n').filter(r => r.trim());
        const isBypass = rules.some(rule => {
            const regex = new RegExp('^' + rule.trim().replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
            return regex.test(address);
        });
        if (isBypass) target = address;
    }

    const remoteSocket = connect({ hostname: target, port: port }, { keepAlive: true });
    const writer = remoteSocket.writable.getWriter();
    await writer.write(firstChunk.slice(offset));
    writer.releaseLock();

    remoteSocket.readable.pipeTo(server.writable);
    server.readable.pipeTo(remoteSocket.writable);
}

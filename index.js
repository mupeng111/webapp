// Minimal VLESS over WebSocket server (Node.js built-ins only).
// Env: UUID (required), WS_PATH (default /ws), PORT (default 8080)
const http = require('http');
const net = require('net');
const crypto = require('crypto');

const UUID_STR = process.env.UUID || '';
const WS_PATH = process.env.WS_PATH || '/ws';
const PORT = parseInt(process.env.PORT || process.env.SERVER_PORT || '8080', 10);
const uuidBytes = Buffer.from(UUID_STR.replace(/-/g, ''), 'hex');

function wsAccept(key) {
  return crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
}

function encodeFrame(data) {
  const len = data.length;
  let head;
  if (len < 126) { head = Buffer.from([0x82, len]); }
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x82; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x82; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([head, data]);
}

// Incremental WebSocket frame parser. Calls onMessage(fullPayload) for
// reassembled binary/text messages, onPing(payload).
class FrameParser {
  constructor(onMessage, onPing, onClose) {
    this.buf = Buffer.alloc(0);
    this.frags = [];
    this.onMessage = onMessage; this.onPing = onPing; this.onClose = onClose;
  }
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0, op = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      const maskOff = off; if (masked) off += 4;
      if (this.buf.length < off + len) return;
      let payload = Buffer.from(this.buf.subarray(off, off + len));
      if (masked) { const m = this.buf.subarray(maskOff, maskOff + 4); for (let i = 0; i < payload.length; i++) payload[i] ^= m[i % 4]; }
      this.buf = this.buf.subarray(off + len);
      if (op === 0x8) { this.onClose(); return; }
      if (op === 0x9) { this.onPing(payload); continue; }
      if (op === 0xA) continue;
      this.frags.push(payload);
      if (fin) { this.onMessage(Buffer.concat(this.frags)); this.frags = []; }
    }
  }
}

function parseVlessHeader(msg) {
  // Returns { host, port, offset } or null.
  if (msg.length < 24) return null;
  if (msg[0] !== 0) return null;
  if (uuidBytes.length === 16 && !msg.subarray(1, 17).equals(uuidBytes)) return null;
  let i = 17;
  const optLen = msg[i]; i += 1 + optLen;
  if (msg[i] !== 1) return null; // TCP only
  i += 1;
  const port = msg.readUInt16BE(i); i += 2;
  const atyp = msg[i]; i += 1;
  let host;
  if (atyp === 1) { host = [...msg.subarray(i, i + 4)].join('.'); i += 4; }
  else if (atyp === 2) { const l = msg[i]; i += 1; host = msg.subarray(i, i + l).toString(); i += l; }
  else if (atyp === 3) {
    const parts = [];
    for (let k = 0; k < 8; k++) { parts.push(msg.readUInt16BE(i).toString(16)); i += 2; }
    host = parts.join(':');
  } else return null;
  return { host, port, offset: i };
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('ok');
});

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname !== WS_PATH) { socket.destroy(); return; }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${wsAccept(key)}\r\n\r\n`);
  if (head && head.length) socket.unshift(head);

  let upstream = null;
  let first = true;
  const parser = new FrameParser((msg) => {
    if (first) {
      first = false;
      const target = parseVlessHeader(msg);
      if (!target) { socket.destroy(); return; }
      upstream = net.connect(target.port, target.host, () => {
        socket.write(encodeFrame(Buffer.from([0, 0])));
        const rest = msg.subarray(target.offset);
        if (rest.length) upstream.write(rest);
      });
      upstream.on('data', (d) => { try { socket.write(encodeFrame(d)); } catch {} });
      upstream.on('error', () => { try { socket.destroy(); } catch {} });
      upstream.on('close', () => { try { socket.destroy(); } catch {} });
    } else if (upstream) {
      upstream.write(msg);
    }
  }, (payload) => {
    // pong: FIN + opcode 0xA
    const frame = Buffer.concat([Buffer.from([0x8a, payload.length]), payload]);
    try { socket.write(frame); } catch {}
  }, () => { try { upstream && upstream.destroy(); } catch {} });

  socket.on('data', (chunk) => { try { parser.push(chunk); } catch { socket.destroy(); } });
  socket.on('error', () => { try { upstream && upstream.destroy(); } catch {} });
  socket.on('close', () => { try { upstream && upstream.destroy(); } catch {} });
});

require('https').get('https://ipinfo.io/json', (res) => {
  let b = '';
  res.on('data', (c) => (b += c));
  res.on('end', () => console.log('egress:', b.slice(0, 300)));
}).on('error', (e) => console.log('egress check failed:', e.message));
server.listen(PORT, () => console.log(`vless-ws listening on :${PORT} path=${WS_PATH}`));

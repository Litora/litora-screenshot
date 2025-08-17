export interface Env {
	IMAGES: KVNamespace;
	WORKER_UPLOAD_SECRET: string;
}

const MAX_BYTES = 5 * 1024 * 1024; // 5 MB
const ALLOWED_MIMES = ['image/png', 'image/jpeg', 'image/webp'];
const TIMESTAMP_WINDOW_SECONDS = 300; // 5 minutes

// Convert ArrayBuffer to lowercase hex.
function toHex(buffer: ArrayBuffer) {
	const u = new Uint8Array(buffer);
	return Array.from(u)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

// Constant-time string equality to avoid timing attacks
function constantTimeEqual(a: string, b: string) {
	if (a.length !== b.length) return false;
	let res = 0;
	for (let i = 0; i < a.length; i++) {
		res |= a.charCodeAt(i) ^ b.charCodeAt(i);
	}
	return res === 0;
}

// Strict mime sniffing: PNG (full 8 bytes), JPEG, WebP (RIFF + 'WEBP')
function sniffMime(buffer: ArrayBuffer): string | null {
	const b = new Uint8Array(buffer);
	if (
		b.length >= 8 &&
		b[0] === 0x89 &&
		b[1] === 0x50 &&
		b[2] === 0x4e &&
		b[3] === 0x47 &&
		b[4] === 0x0d &&
		b[5] === 0x0a &&
		b[6] === 0x1a &&
		b[7] === 0x0a
	) {
		return 'image/png';
	}
	if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
		return 'image/jpeg';
	}
	if (
		b.length >= 12 &&
		b[0] === 0x52 &&
		b[1] === 0x49 &&
		b[2] === 0x46 &&
		b[3] === 0x46 &&
		b[8] === 0x57 &&
		b[9] === 0x45 &&
		b[10] === 0x42 &&
		b[11] === 0x50
	) {
		return 'image/webp';
	}
	return null;
}

// Validate hex signature format (SHA-256 -> 64 hex chars)
function isHex64(s: string) {
	return /^[0-9a-fA-F]{64}$/.test(s);
}

// Parse and require integer-only timestamp
function isFreshTimestamp(tsStr: string, windowSeconds = TIMESTAMP_WINDOW_SECONDS) {
	if (!/^\d+$/.test(tsStr)) return false;
	const ts = Number(tsStr);
	const now = Math.floor(Date.now() / 1000);
	return Math.abs(now - ts) <= windowSeconds;
}

// Read body via stream and reject early if it exceeds max bytes.
// This avoids pulling arbitrarily large payloads into memory.
async function readBodyLimited(request: Request, maxBytes: number): Promise<ArrayBuffer> {
	const body = request.body;
	if (!body) return new ArrayBuffer(0);

	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let received = 0;

	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		if (value) {
			received += value.byteLength;
			if (received > maxBytes) {
				// best-effort cancel
				try {
					reader.cancel();
				} catch (e) {}
				const err: any = new Error('PAYLOAD_TOO_LARGE');
				err.code = 'PAYLOAD_TOO_LARGE';
				throw err;
			}
			chunks.push(value);
		}
	}

	const out = new Uint8Array(received);
	let offset = 0;
	for (const c of chunks) {
		out.set(c, offset);
		offset += c.byteLength;
	}
	return out.buffer;
}

// Basic CORS helper (tweak origin in production)
function withCorsHeaders(res: Response) {
	res.headers.set('Access-Control-Allow-Origin', '*');
	res.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
	res.headers.set('Access-Control-Allow-Headers', 'Content-Type, x-upload-timestamp, x-upload-signature');
	return res;
}

// --- CryptoKey cache (performance) ---
const keyCache = new Map<string, CryptoKey>();

async function getHmacKey(secret: string): Promise<CryptoKey> {
	const cached = keyCache.get(secret);
	if (cached) return cached;
	const encoder = new TextEncoder();
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	keyCache.set(secret, key);
	return key;
}

async function computeHmacHexCached(secret: string, timestamp: string, body: ArrayBuffer) {
	const key = await getHmacKey(secret);
	const encoder = new TextEncoder();
	const tsBytes = encoder.encode(timestamp + '.');
	const payload = new Uint8Array(tsBytes.length + body.byteLength);
	payload.set(tsBytes, 0);
	payload.set(new Uint8Array(body), tsBytes.length);
	const sig = await crypto.subtle.sign('HMAC', key, payload);
	return toHex(sig);
}

// --- Main fetch handler ---
export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		// CORS preflight
		if (request.method === 'OPTIONS') {
			return withCorsHeaders(new Response(null, { status: 204 }));
		}

		// UPLOAD endpoint
		if (request.method === 'POST' && url.pathname === '/upload') {
			const sigHeader = (request.headers.get('x-upload-signature') || '').trim();
			const tsHeader = (request.headers.get('x-upload-timestamp') || '').trim();

			if (!sigHeader || !tsHeader) {
				return withCorsHeaders(new Response('Missing authentication headers', { status: 401 }));
			}

			// Validate header formats early
			if (!isHex64(sigHeader)) {
				return withCorsHeaders(new Response('Invalid signature format', { status: 400 }));
			}
			if (!/^\d+$/.test(tsHeader)) {
				return withCorsHeaders(new Response('Invalid timestamp format', { status: 400 }));
			}

			if (!isFreshTimestamp(tsHeader)) {
				return withCorsHeaders(new Response('Stale or invalid timestamp', { status: 401 }));
			}

			const secret = env.WORKER_UPLOAD_SECRET;
			if (!secret) return withCorsHeaders(new Response('Server misconfigured', { status: 500 }));

			// Read body with limit to avoid reading too much into memory
			let bodyBuf: ArrayBuffer;
			try {
				bodyBuf = await readBodyLimited(request, MAX_BYTES);
			} catch (err: any) {
				if (err?.code === 'PAYLOAD_TOO_LARGE') {
					return withCorsHeaders(new Response('Payload too large', { status: 413 }));
				}
				return withCorsHeaders(new Response('Failed to read body', { status: 400 }));
			}

			if (bodyBuf.byteLength === 0) return withCorsHeaders(new Response('Empty body', { status: 400 }));

			// Verify signature using cached CryptoKey
			try {
				const expected = await computeHmacHexCached(secret, tsHeader, bodyBuf);
				if (!constantTimeEqual(expected.toLowerCase(), sigHeader.toLowerCase())) {
					return withCorsHeaders(new Response('Invalid signature', { status: 403 }));
				}
			} catch (err) {
				console.error('HMAC verification error:', err);
				return withCorsHeaders(new Response('Signature verification failed', { status: 500 }));
			}

			// Sniff mime
			const mime = sniffMime(bodyBuf);
			if (!mime || !ALLOWED_MIMES.includes(mime)) {
				return withCorsHeaders(new Response('Unsupported media type', { status: 415 }));
			}

			// Use a single key "latest" to avoid creating multiple keys.
			const key = 'latest';
			try {
				await env.IMAGES.put(key, bodyBuf, {
					metadata: { contentType: mime },
				});
			} catch (err) {
				console.error('KV put error:', err);
				return withCorsHeaders(new Response('Failed to store image', { status: 500 }));
			}

			const respBody = JSON.stringify({ ok: true, key, url: `${url.origin}/image` });
			const res = new Response(respBody, { status: 200, headers: { 'content-type': 'application/json' } });
			return withCorsHeaders(res);
		}

		// SERVE LATEST IMAGE
		if (request.method === 'GET' && url.pathname === '/image') {
			const key = 'latest';
			try {
				const getWithMeta = (env.IMAGES as any).getWithMetadata?.bind(env.IMAGES);
				if (getWithMeta) {
					const res = (await getWithMeta(key, { type: 'arrayBuffer' })) as {
						value: ArrayBuffer | null;
						metadata?: Record<string, any>;
					} | null;
					if (res?.value) {
						const contentType = res.metadata?.contentType ?? 'application/octet-stream';
						const headers = new Headers();
						headers.set('Content-Type', contentType);
						headers.set('Cache-Control', 'public, max-age=60, s-maxage=300');
						const out = new Response(res.value, { headers });
						return withCorsHeaders(out);
					}
				} else {
					const value = (await (env.IMAGES as any).get(key, { type: 'arrayBuffer' })) as ArrayBuffer | null;
					if (value) {
						const meta = (await (env.IMAGES as any).getMetadata?.(key)) as Record<string, any> | undefined;
						const contentType = meta?.contentType ?? 'application/octet-stream';
						const headers = new Headers();
						headers.set('Content-Type', contentType);
						headers.set('Cache-Control', 'public, max-age=60, s-maxage=300');
						const out = new Response(value, { headers });
						return withCorsHeaders(out);
					}
				}
			} catch (err) {
				console.error('KV get error for latest', err);
			}
			return withCorsHeaders(new Response('No image available', { status: 404 }));
		}

		return new Response('Not found', { status: 404 });
	},
};

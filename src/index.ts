export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname === '/update' && request.method === 'POST') {
			const body = await request.arrayBuffer();
			await env.IMAGES.put('latest', body);
			return new Response('Image updated', { status: 200 });
		}

		if (url.pathname === '/image') {
			const image = await env.IMAGES.get('latest', { type: 'arrayBuffer' });

			if (!image) {
				return new Response('No image found', { status: 404 });
			}

			return new Response(image, {
				status: 200,
				headers: {
					'content-type': 'image/png',
					'cache-control': 'no-store',
				},
			});
		}

		return new Response('Not found', { status: 404 });
	},
};
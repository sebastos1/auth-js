import { oauth } from '$lib/server/auth';
import type { RequestHandler } from './$types';

export const GET: RequestHandler = async ({ request, params }) => {
    const apiPath = `/${params.path}`;
    // Create a new URL with the API path, preserving query params
    const url = new URL(request.url);
    url.pathname = apiPath;

    return await oauth.fetchApi(new Request(url.toString(), {
        method: 'GET',
        headers: request.headers
    }));
};

export const POST: RequestHandler = async ({ request, params }) => {
    const apiPath = `/${params.path}`;
    const url = new URL(request.url);
    url.pathname = apiPath;

    return await oauth.fetchApi(new Request(url.toString(), {
        method: 'POST',
        headers: request.headers,
        body: await request.blob() // Handle body properly
    }));
};

export const PUT: RequestHandler = async ({ request, params }) => {
    const apiPath = `/${params.path}`;
    const url = new URL(request.url);
    url.pathname = apiPath;

    return await oauth.fetchApi(new Request(url.toString(), {
        method: 'PUT',
        headers: request.headers,
        body: await request.blob()
    }));
};

export const DELETE: RequestHandler = async ({ request, params }) => {
    const apiPath = `/${params.path}`;
    const url = new URL(request.url);
    url.pathname = apiPath;

    return await oauth.fetchApi(new Request(url.toString(), {
        method: 'DELETE',
        headers: request.headers
    }));
};
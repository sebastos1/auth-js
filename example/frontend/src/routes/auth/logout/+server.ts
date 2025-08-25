import { oauth } from '$lib/server/auth';

export async function POST({ request }) {
    return await oauth.logout(request);
}
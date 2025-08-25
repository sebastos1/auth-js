import { oauth } from '$lib/server/auth';

export async function GET({ request }) {
    return await oauth.login(request);
}
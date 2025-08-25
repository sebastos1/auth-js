<script lang="ts">
    import OAuth2Client from 'sjallabong-auth/client';
    
    const auth = new OAuth2Client({});

    let user = $state(auth.getUser());
    let loading = $state(false);
    let error = $state('');

    async function handleLogin(usePopup = true) {
        loading = true;
        error = '';
        
        try {
            const userData = await auth.login(usePopup);
            user = userData;
            console.log('Login successful:', userData);
        } catch (err) {
            error = (err as Error).message;
            
            if (error === 'Failed to open popup') {
                console.log('Popup blocked, trying redirect...');
                await auth.login(false);
            }
        } finally {
            loading = false;
        }
    }

    async function handleLogout() {
        loading = true;
        try {
            await auth.logout();
            user = null;
        } catch (err) {
            error = (err as Error).message;
        } finally {
            loading = false;
        }
    }

    let apiResponse = $state<{ error?: string } | null>(null);
    let apiLoading = $state(false);

    async function testApi() {
        apiLoading = true;
        try {
            const response = await auth.callApi('/test/hello?name=testuser&count=42');
            apiResponse = await response.json();
        } catch (err) {
            apiResponse = { error: (err as Error).message };
        } finally {
            apiLoading = false;
        }
    }

    $effect(() => {
        auth.checkAuth().then((userData: any) => {
            user = userData;
        });
    });
</script>

<h1>Welcome to SvelteKit</h1>
<p>Visit <a href="https://svelte.dev/docs/kit">svelte.dev/docs/kit</a> to read the documentation</p>

<div>
    {#if loading}
        <p>Loading...</p>
    {:else if user}
        <div>
            <div>
                <p>Welcome, {user.username}!</p>
            </div>
            <button onclick={() => handleLogout()}>Logout</button>
            <button onclick={() => testApi()}>Test API</button>
        
            {#if apiLoading}
                <p>Loading API...</p>
            {:else if apiResponse}
                <pre>{JSON.stringify(apiResponse, null, 2)}</pre>
            {/if}
        </div>
    {:else}
        <div>
            <button onclick={() => handleLogin(true)}>Login (Popup)</button>
            <button onclick={() => handleLogin(false)}>Login (Redirect)</button>
        </div>
    {/if}
    
    {#if error}
        <p style="color: red;">Error: {error}</p>
    {/if}
</div>
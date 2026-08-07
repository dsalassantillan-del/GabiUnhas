import { createClient } from
    'https://esm.sh/@supabase/supabase-js@2';

function redirectResponse(
    appUrl: string,
    status: 'success' | 'error',
    message?: string
) {
    const destination = new URL(appUrl);

    destination.searchParams.set(
        'calendar_connection',
        status
    );

    if (message) {
        destination.searchParams.set(
            'calendar_message',
            message
        );
    }

    return Response.redirect(
        destination.toString(),
        302
    );
}

Deno.serve(async (request) => {
    const appUrl =
        Deno.env.get('APP_URL') || '';

    try {
        if (request.method !== 'GET') {
            return new Response(
                'Método não permitido.',
                { status: 405 }
            );
        }

        if (!appUrl) {
            throw new Error(
                'APP_URL não configurada.'
            );
        }

        const requestUrl =
            new URL(request.url);

        const oauthError =
            requestUrl.searchParams.get('error');

        if (oauthError) {
            console.error(
                'Google devolveu erro OAuth:',
                oauthError
            );

            return redirectResponse(
                appUrl,
                'error',
                'Autorização cancelada ou recusada.'
            );
        }

        const code =
            requestUrl.searchParams.get('code');

        const state =
            requestUrl.searchParams.get('state');

        if (!code || !state) {
            return redirectResponse(
                appUrl,
                'error',
                'Resposta de autorização incompleta.'
            );
        }

        const supabaseUrl =
            Deno.env.get('SUPABASE_URL');

        const serviceRoleKey =
            Deno.env.get(
                'SUPABASE_SERVICE_ROLE_KEY'
            );

        const googleClientId =
            Deno.env.get('GOOGLE_CLIENT_ID');

        const googleClientSecret =
            Deno.env.get(
                'GOOGLE_CLIENT_SECRET'
            );

        const googleRedirectUri =
            Deno.env.get(
                'GOOGLE_REDIRECT_URI'
            );

        if (
            !supabaseUrl ||
            !serviceRoleKey ||
            !googleClientId ||
            !googleClientSecret ||
            !googleRedirectUri
        ) {
            throw new Error(
                'Configuração incompleta da função.'
            );
        }

        const supabaseAdmin =
            createClient(
                supabaseUrl,
                serviceRoleKey,
                {
                    auth: {
                        persistSession: false,
                        autoRefreshToken: false
                    }
                }
            );

        /*
         * El state se elimina al consumirlo.
         * No puede reutilizarse posteriormente.
         */
        const {
            data: userId,
            error: stateError
        } = await supabaseAdmin.rpc(
            'consume_google_oauth_state',
            {
                p_state: state
            }
        );

        if (stateError) {
            throw stateError;
        }

        if (!userId) {
            return redirectResponse(
                appUrl,
                'error',
                'Autorização expirada ou inválida.'
            );
        }

        /*
         * Intercambia el código de un solo uso por
         * access token y refresh token.
         */
        const tokenResponse = await fetch(
            'https://oauth2.googleapis.com/token',
            {
                method: 'POST',
                headers: {
                    'Content-Type':
                        'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    code,
                    client_id: googleClientId,
                    client_secret:
                        googleClientSecret,
                    redirect_uri:
                        googleRedirectUri,
                    grant_type:
                        'authorization_code'
                })
            }
        );

        const tokenData =
            await tokenResponse.json();

        if (!tokenResponse.ok) {
            console.error(
                'Erro na troca do código.'
            );

            throw new Error(
                'Google não devolveu tokens válidos.'
            );
        }

        if (
            !tokenData.access_token ||
            !tokenData.refresh_token
        ) {
            console.error(
                'Resposta sem refresh token.'
            );

            throw new Error(
                'Google não devolveu o token de renovação.'
            );
        }

        const expiresAt =
            new Date(
                Date.now() +
                Number(
                    tokenData.expires_in || 3600
                ) *
                1000
            ).toISOString();

        /*
         * Obtiene el correo de la cuenta Google
         * que autorizó Calendar.
         */
        let googleEmail: string | null = null;

        try {
            const userInfoResponse =
                await fetch(
                    'https://openidconnect.googleapis.com/v1/userinfo',
                    {
                        headers: {
                            Authorization:
                                `Bearer ${tokenData.access_token}`
                        }
                    }
                );

            if (userInfoResponse.ok) {
                const userInfo =
                    await userInfoResponse.json();

                googleEmail =
                    userInfo.email || null;
            }
        } catch (userInfoError) {
            console.error(
                'Não foi possível obter o e-mail Google:',
                userInfoError
            );
        }

        const { error: tokenSaveError } =
            await supabaseAdmin.rpc(
                'save_google_calendar_tokens',
                {
                    p_user_id: userId,
                    p_access_token:
                        tokenData.access_token,
                    p_refresh_token:
                        tokenData.refresh_token,
                    p_token_type:
                        tokenData.token_type ||
                        'Bearer',
                    p_scopes:
                        tokenData.scope || null,
                    p_access_token_expires_at:
                        expiresAt
                }
            );

        if (tokenSaveError) {
            throw tokenSaveError;
        }

        /*
         * Solo guarda información segura en
         * la tabla pública.
         */
        const { error: connectionError } =
            await supabaseAdmin
                .from(
                    'google_calendar_connections'
                )
                .upsert(
                    {
                        user_id: userId,
                        google_email:
                            googleEmail,
                        calendar_id: 'primary',
                        is_active: true,
                        connected_at:
                            new Date().toISOString(),
                        disconnected_at: null,
                        updated_at:
                            new Date().toISOString()
                    },
                    {
                        onConflict: 'user_id'
                    }
                );

        if (connectionError) {
            throw connectionError;
        }

        return redirectResponse(
            appUrl,
            'success'
        );

    } catch (error) {
        console.error(
            'Erro em google-calendar-callback:',
            error
        );

        if (appUrl) {
            return redirectResponse(
                appUrl,
                'error',
                'Não foi possível conectar o Google Calendar.'
            );
        }

        return new Response(
            'Não foi possível conectar o Google Calendar.',
            { status: 500 }
        );
    }
});

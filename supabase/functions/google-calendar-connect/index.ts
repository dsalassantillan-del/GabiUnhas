import { createClient } from
    'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers':
        'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
};

Deno.serve(async (request) => {
    if (request.method === 'OPTIONS') {
        return new Response('ok', {
            headers: corsHeaders
        });
    }

    try {
        if (request.method !== 'POST') {
            return new Response(
                JSON.stringify({
                    error: 'Método não permitido.'
                }),
                {
                    status: 405,
                    headers: {
                        ...corsHeaders,
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        const authorizationHeader =
            request.headers.get('Authorization');

        if (!authorizationHeader?.startsWith('Bearer ')) {
            return new Response(
                JSON.stringify({
                    error: 'Sessão não encontrada.'
                }),
                {
                    status: 401,
                    headers: {
                        ...corsHeaders,
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        const accessToken =
            authorizationHeader.replace('Bearer ', '');

        const supabaseUrl =
            Deno.env.get('SUPABASE_URL');

        const serviceRoleKey =
            Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

        const googleClientId =
            Deno.env.get('GOOGLE_CLIENT_ID');

        const googleRedirectUri =
            Deno.env.get('GOOGLE_REDIRECT_URI');

        if (
            !supabaseUrl ||
            !serviceRoleKey ||
            !googleClientId ||
            !googleRedirectUri
        ) {
            throw new Error(
                'Configuração incompleta da função.'
            );
        }

        const supabaseAdmin = createClient(
            supabaseUrl,
            serviceRoleKey,
            {
                auth: {
                    persistSession: false,
                    autoRefreshToken: false
                }
            }
        );

        const {
            data: { user },
            error: userError
        } = await supabaseAdmin.auth.getUser(
            accessToken
        );

        if (userError || !user) {
            return new Response(
                JSON.stringify({
                    error: 'Sessão inválida ou expirada.'
                }),
                {
                    status: 401,
                    headers: {
                        ...corsHeaders,
                        'Content-Type': 'application/json'
                    }
                }
            );
        }

        const state = crypto.randomUUID();

        const expiresAt =
            new Date(
                Date.now() + 10 * 60 * 1000
            ).toISOString();

        // Elimina estados anteriores del mismo usuario.
        const { error: stateError } =
            await supabaseAdmin.rpc(
                'create_google_oauth_state',
                {
                    p_user_id: user.id,
                    p_state: state,
                    p_expires_at: expiresAt
                }
            );

        if (stateError) {
            throw stateError;
        }

        const params = new URLSearchParams({
            client_id: googleClientId,
            redirect_uri: googleRedirectUri,
            response_type: 'code',

            scope: [
                'openid',
                'email',
                'https://www.googleapis.com/auth/calendar.events'
            ].join(' '),

            access_type: 'offline',
            prompt: 'consent',
            include_granted_scopes: 'true',
            state
        });

        const authorizationUrl =
            `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;

        return new Response(
            JSON.stringify({
                authorizationUrl
            }),
            {
                status: 200,
                headers: {
                    ...corsHeaders,
                    'Content-Type': 'application/json'
                }
            }
        );

    } catch (error) {
        console.error(
            'Erro em google-calendar-connect:',
            error
        );

        return new Response(
            JSON.stringify({
                error:
                    'Não foi possível iniciar a conexão com o Google Calendar.'
            }),
            {
                status: 500,
                headers: {
                    ...corsHeaders,
                    'Content-Type': 'application/json'
                }
            }
        );
    }
});

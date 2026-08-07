import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers':
        'authorization, x-client-info, apikey, content-type',
};

type GoogleCalendarTokens = {
    access_token?: string | null;
    refresh_token?: string | null;
};

Deno.serve(async (request) => {
    if (request.method === 'OPTIONS') {
        return new Response('ok', { headers: corsHeaders });
    }

    if (request.method !== 'POST') {
        return jsonResponse(
            { error: 'Método não permitido.' },
            405,
        );
    }

    try {
        const authorization = request.headers.get('Authorization');

        if (!authorization) {
            return jsonResponse(
                { error: 'Sessão não encontrada.' },
                401,
            );
        }

        const supabaseUrl = requireEnv('SUPABASE_URL');
        const supabaseAnonKey = requireEnv('SUPABASE_ANON_KEY');
        const supabaseServiceRoleKey = requireEnv(
            'SUPABASE_SERVICE_ROLE_KEY',
        );

        const userClient = createClient(
            supabaseUrl,
            supabaseAnonKey,
            {
                global: {
                    headers: { Authorization: authorization },
                },
                auth: {
                    persistSession: false,
                    autoRefreshToken: false,
                },
            },
        );

        const {
            data: { user },
            error: userError,
        } = await userClient.auth.getUser();

        if (userError || !user) {
            return jsonResponse(
                { error: 'Sessão inválida ou expirada.' },
                401,
            );
        }

        const adminClient = createClient(
            supabaseUrl,
            supabaseServiceRoleKey,
            {
                auth: {
                    persistSession: false,
                    autoRefreshToken: false,
                },
            },
        );

        const { data: tokenData, error: tokenError } =
            await adminClient.rpc(
                'get_google_calendar_tokens',
                { p_user_id: user.id },
            );

        let revocationWarning: string | null = null;

        if (tokenError) {
            revocationWarning =
                `Não foi possível obter o token para revogação: ${tokenError.message}`;
        }

        const tokens = tokenError ? null : normalizeTokens(tokenData);
        let revoked = false;

        const tokenToRevoke =
            tokens?.refresh_token || tokens?.access_token;

        if (tokenToRevoke) {
            try {
                const revokeResponse = await fetch(
                    'https://oauth2.googleapis.com/revoke',
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type':
                                'application/x-www-form-urlencoded',
                        },
                        body: new URLSearchParams({
                            token: tokenToRevoke,
                        }),
                    },
                );

                revoked = revokeResponse.ok;

                if (!revokeResponse.ok) {
                    revocationWarning =
                        `Google respondeu com status ${revokeResponse.status}.`;
                }
            } catch (error) {
                revocationWarning =
                    error instanceof Error
                        ? error.message
                        : 'Falha ao contatar o Google.';
            }
        }

        const { error: disconnectError } = await adminClient.rpc(
            'disconnect_google_calendar',
            { p_user_id: user.id },
        );

        if (disconnectError) {
            throw new Error(
                `Não foi possível limpar a conexão local: ${disconnectError.message}`,
            );
        }

        return jsonResponse({
            disconnected: true,
            googleAuthorizationRevoked: revoked,
            revocationWarning,
        });
    } catch (error) {
        console.error('Erro ao desconectar Google Calendar:', error);

        return jsonResponse(
            {
                error:
                    error instanceof Error
                        ? error.message
                        : 'Erro interno ao desconectar Google Calendar.',
            },
            500,
        );
    }
});

function normalizeTokens(data: unknown): GoogleCalendarTokens | null {
    if (Array.isArray(data)) {
        return (data[0] as GoogleCalendarTokens | undefined) || null;
    }

    if (data && typeof data === 'object') {
        return data as GoogleCalendarTokens;
    }

    return null;
}

function requireEnv(name: string): string {
    const value = Deno.env.get(name);

    if (!value) {
        throw new Error(`Variável de ambiente ausente: ${name}`);
    }

    return value;
}

function jsonResponse(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), {
        status,
        headers: {
            ...corsHeaders,
            'Content-Type': 'application/json',
        },
    });
}

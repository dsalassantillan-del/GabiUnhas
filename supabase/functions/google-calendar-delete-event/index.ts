import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function jsonResponse(
  body: Record<string, unknown>,
  status = 200,
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", {
      headers: corsHeaders,
    });
  }

  if (req.method !== "POST") {
    return jsonResponse(
      { error: "Método no permitido" },
      405,
    );
  }

  try {
    const supabaseUrl =
      Deno.env.get("SUPABASE_URL");

    const supabaseAnonKey =
      Deno.env.get("SUPABASE_ANON_KEY");

    const serviceRoleKey =
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

    const googleClientId =
      Deno.env.get("GOOGLE_CLIENT_ID");

    const googleClientSecret =
      Deno.env.get("GOOGLE_CLIENT_SECRET");

    if (
      !supabaseUrl ||
      !supabaseAnonKey ||
      !serviceRoleKey ||
      !googleClientId ||
      !googleClientSecret
    ) {
      throw new Error(
        "Faltan variables de entorno",
      );
    }

    const authorization =
      req.headers.get("Authorization");

    if (!authorization) {
      return jsonResponse(
        { error: "Sesión no encontrada" },
        401,
      );
    }

    const jwt =
      authorization.replace("Bearer ", "");

    const supabaseAuth = createClient(
      supabaseUrl,
      supabaseAnonKey,
      {
        global: {
          headers: {
            Authorization: authorization,
          },
        },
      },
    );

    const {
      data: { user },
      error: userError,
    } = await supabaseAuth.auth.getUser(jwt);

    if (userError || !user) {
      return jsonResponse(
        { error: "Sesión inválida" },
        401,
      );
    }

    const supabaseAdmin = createClient(
      supabaseUrl,
      serviceRoleKey,
    );

    const body = await req.json();

    const appointmentId =
      body?.appointmentId;

    if (!appointmentId) {
      return jsonResponse(
        {
          error:
            "El appointmentId es obligatorio",
        },
        400,
      );
    }

    /*
     * Obtener la cita y comprobar que
     * pertenece al usuario autenticado.
     */
    const {
      data: appointment,
      error: appointmentError,
    } = await supabaseAdmin
      .from("appointments")
      .select(`
        id,
        user_id,
        google_calendar_event_id
      `)
      .eq("id", appointmentId)
      .eq("user_id", user.id)
      .maybeSingle();

    if (appointmentError) {
      throw appointmentError;
    }

    if (!appointment) {
      return jsonResponse(
        { error: "Cita no encontrada" },
        404,
      );
    }

    /*
     * Si esta cita nunca tuvo evento de Google,
     * no hay nada que borrar allí.
     */
    if (!appointment.google_calendar_event_id) {
      return jsonResponse({
        success: true,
        skipped: true,
        reason:
          "La cita no tiene evento de Google Calendar",
      });
    }

    /*
     * Obtener la configuración del Calendar.
     */
    const {
      data: connection,
      error: connectionError,
    } = await supabaseAdmin
      .from("google_calendar_connections")
      .select("calendar_id, is_active")
      .eq("user_id", user.id)
      .maybeSingle();

    if (connectionError) {
      throw connectionError;
    }

    if (!connection?.is_active) {
      return jsonResponse(
        {
          error:
            "Google Calendar no está conectado",
          code:
            "GOOGLE_CALENDAR_NOT_CONNECTED",
        },
        409,
      );
    }

    /*
     * Obtener los tokens privados.
     */
    const {
      data: tokenRows,
      error: tokenError,
    } = await supabaseAdmin.rpc(
      "get_google_calendar_tokens",
      {
        p_user_id: user.id,
      },
    );

    if (tokenError) {
      throw tokenError;
    }

    const tokens = tokenRows?.[0];

    if (!tokens?.refresh_token) {
      return jsonResponse(
        {
          error:
            "No se encontraron los tokens de Google",
        },
        409,
      );
    }

    let accessToken =
      tokens.access_token;

    const expiresAt =
      tokens.access_token_expires_at
        ? new Date(
            tokens.access_token_expires_at,
          ).getTime()
        : 0;

    const shouldRefresh =
      !accessToken ||
      expiresAt <=
        Date.now() + 5 * 60 * 1000;

    /*
     * Renovar access token cuando sea necesario.
     */
    if (shouldRefresh) {
      const refreshBody =
        new URLSearchParams({
          client_id: googleClientId,
          client_secret:
            googleClientSecret,
          refresh_token:
            tokens.refresh_token,
          grant_type: "refresh_token",
        });

      const refreshResponse =
        await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded",
            },
            body: refreshBody,
          },
        );

      const refreshData =
        await refreshResponse.json();

      if (!refreshResponse.ok) {
        console.error(
          "Error al renovar token:",
          refreshData,
        );

        return jsonResponse(
          {
            error:
              "No se pudo renovar la autorización de Google",
          },
          401,
        );
      }

      accessToken =
        refreshData.access_token;

      const expiresIn =
        Number(
          refreshData.expires_in ?? 3600,
        );

      const newExpiration =
        new Date(
          Date.now() +
            expiresIn * 1000,
        ).toISOString();

      const {
        error: updateTokenError,
      } = await supabaseAdmin.rpc(
        "update_google_calendar_access_token",
        {
          p_user_id: user.id,
          p_access_token: accessToken,
          p_access_token_expires_at:
            newExpiration,
          p_token_type:
            refreshData.token_type ??
            "Bearer",
          p_scopes:
            refreshData.scope ?? null,
        },
      );

      if (updateTokenError) {
        throw updateTokenError;
      }
    }

    const calendarId =
      connection.calendar_id ||
      "primary";

    const eventId =
      appointment.google_calendar_event_id;

    /*
     * Eliminar el evento en Google.
     */
    const googleResponse =
      await fetch(
        `https://www.googleapis.com/calendar/v3/calendars/${
          encodeURIComponent(calendarId)
        }/events/${
          encodeURIComponent(eventId)
        }`,
        {
          method: "DELETE",
          headers: {
            Authorization:
              `Bearer ${accessToken}`,
          },
        },
      );

    /*
     * 204 = eliminado correctamente.
     * 404 = ya no existe en Google.
     *
     * En ambos casos podemos considerar
     * que Google ya está limpio.
     */
    if (
      !googleResponse.ok &&
      googleResponse.status !== 404
    ) {
      const googleError =
        await googleResponse.text();

      console.error(
        "Error de Google Calendar:",
        googleError,
      );

      return jsonResponse(
        {
          error:
            "No se pudo eliminar el evento de Google Calendar",
          status:
            googleResponse.status,
        },
        googleResponse.status,
      );
    }

    return jsonResponse({
      success: true,
      googleEventDeleted: true,
    });

  } catch (error) {
    console.error(
      "Error completo en google-calendar-delete-event:",
      error,
    );

    const errorDetails =
      error &&
      typeof error === "object"
        ? {
            message:
              "message" in error
                ? String(error.message)
                : "Error sin mensaje",

            code:
              "code" in error
                ? String(error.code)
                : null,

            details:
              "details" in error
                ? String(error.details)
                : null,

            hint:
              "hint" in error
                ? String(error.hint)
                : null,
          }
        : {
            message: String(error),
            code: null,
            details: null,
            hint: null,
          };

    return jsonResponse(
      {
        error: errorDetails.message,
        code: errorDetails.code,
        details: errorDetails.details,
        hint: errorDetails.hint,
      },
      500,
    );
  }
});

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

    const jwt = authorization.replace(
      "Bearer ",
      "",
    );

    /*
     * Cliente para validar al usuario.
     * No utiliza service_role para autenticarlo.
     */
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

    /*
     * Cliente administrativo.
     * Solo se usa dentro de la Edge Function.
     */
    const supabaseAdmin = createClient(
      supabaseUrl,
      serviceRoleKey,
    );

    const requestBody = await req.json();
    const appointmentId =
      requestBody?.appointmentId;

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
     * Busca la cita y verifica que pertenezca
     * al usuario autenticado.
     */
    const {
      data: appointment,
      error: appointmentError,
    } = await supabaseAdmin
      .from("appointments")
      .select(`
        id,
        user_id,
        appointment_date,
        client_name,
        service_name,
        price,
        start_time,
        end_time,
        status,
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
     * Evita crear el mismo evento dos veces.
     */
    if (
      appointment.google_calendar_event_id
    ) {
      return jsonResponse({
        success: true,
        alreadySynced: true,
        googleCalendarEventId:
          appointment.google_calendar_event_id,
      });
    }

    /*
     * Confirma que Calendar esté activo.
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
          code: "GOOGLE_CALENDAR_NOT_CONNECTED",
        },
        409,
      );
    }

    /*
     * Lee los tokens mediante la RPC privada.
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

    /*
     * Se renueva cinco minutos antes de vencer.
     */
    const shouldRefresh =
      !accessToken ||
      expiresAt <= Date.now() + 5 * 60 * 1000;

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
            googleError: refreshData,
          },
          401,
        );
      }

      accessToken =
        refreshData.access_token;

      const expiresIn =
        Number(refreshData.expires_in ?? 3600);

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
            refreshData.scope ??
            null,
        },
      );

      if (updateTokenError) {
        throw updateTokenError;
      }
    }

    /*
     * Las columnas date y time están separadas.
     * Se construyen fechas con zona horaria de Brasil.
     */
    const startDateTime =
      `${appointment.appointment_date}` +
      `T${appointment.start_time}`;

    const endDateTime =
      `${appointment.appointment_date}` +
      `T${appointment.end_time}`;

    const calendarId =
      connection.calendar_id ||
      "primary";

    const eventBody = {
      summary:
        `${appointment.client_name} - ` +
        `${appointment.service_name}`,

      description:
        `Cliente: ${appointment.client_name}\n` +
        `Servicio: ${appointment.service_name}\n` +
        `Valor: R$ ${appointment.price}`,

      start: {
        dateTime: startDateTime,
        timeZone: "America/Sao_Paulo",
      },

      end: {
        dateTime: endDateTime,
        timeZone: "America/Sao_Paulo",
      },

      extendedProperties: {
        private: {
          appointment_id:
            appointment.id,
          supabase_user_id:
            appointment.user_id,
        },
      },
    };

    const googleResponse =
      await fetch(
        `https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)
        }/events`,
        {
          method: "POST",
          headers: {
            Authorization:
              `Bearer ${accessToken}`,
            "Content-Type":
              "application/json",
          },
          body: JSON.stringify(
            eventBody,
          ),
        },
      );

    const googleEvent =
      await googleResponse.json();

    if (!googleResponse.ok) {
      console.error(
        "Error de Google Calendar:",
        googleEvent,
      );

      return jsonResponse(
        {
          error:
            "Google Calendar rechazó el evento",
          googleError: googleEvent,
        },
        googleResponse.status,
      );
    }

    const {
      error: updateAppointmentError,
    } = await supabaseAdmin
      .from("appointments")
      .update({
        google_calendar_event_id:
          googleEvent.id,
        updated_at:
          new Date().toISOString(),
      })
      .eq("id", appointment.id)
      .eq("user_id", user.id);

    if (updateAppointmentError) {
      /*
       * El evento ya se creó en Google, por eso
       * registramos claramente este error.
       */
      console.error(
        "Evento creado pero no guardado en Supabase:",
        {
          googleEventId:
            googleEvent.id,
          error:
            updateAppointmentError,
        },
      );

      return jsonResponse(
        {
          error:
            "El evento se creó en Google, pero no se pudo guardar su ID",
          googleCalendarEventId:
            googleEvent.id,
        },
        500,
      );
    }

    return jsonResponse({
      success: true,
      googleCalendarEventId:
        googleEvent.id,
      htmlLink:
        googleEvent.htmlLink,
    });
  } catch (error) {
    console.error(
      "Error completo en google-calendar-create-event:",
      error,
    );

    const errorDetails =
      error && typeof error === "object"
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

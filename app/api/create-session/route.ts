export const runtime = "edge";

interface CreateSessionRequestBody {
  workflow?: { id?: string | null } | null;
  scope?: { user_id?: string | null } | null;
  workflowId?: string | null;
  chatkit_configuration?: {
    file_upload?: {
      enabled?: boolean;
    };
  };
}

const CHATKIT_URL = "https://api.openai.com/v1/chatkit/sessions";

const SESSION_COOKIE_NAME = "chatkit_session_id";
const SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

export async function POST(request: Request): Promise<Response> {
  // Next will only route POST here, but keeping this makes the handler explicit.
  if (request.method !== "POST") {
    return methodNotAllowedResponse();
  }

  let sessionCookie: string | null = null;

  try {
    const openaiApiKey = process.env.OPENAI_API_KEY;
    if (!openaiApiKey) {
      return json(
        { error: "Missing OPENAI_API_KEY environment variable" },
        500
      );
    }

    const parsedBody = await safeParseJson<CreateSessionRequestBody>(request);

    const { userId, sessionCookie: newSessionCookie } = await resolveUserId(
      request
    );
    sessionCookie = newSessionCookie;

    const resolvedWorkflowId =
      parsedBody?.workflow?.id ??
      parsedBody?.workflowId ??
      process.env.NEXT_PUBLIC_CHATKIT_WORKFLOW_ID ??
      null;

    if (!resolvedWorkflowId) {
      return jsonWithCookie(
        { error: "Missing workflow id" },
        400,
        sessionCookie
      );
    }

    const upstreamResponse = await fetch(CHATKIT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${openaiApiKey}`,
        "OpenAI-Beta": "chatkit_beta=v1",
      },
      body: JSON.stringify({
        workflow: { id: resolvedWorkflowId },
        user: userId,
        chatkit_configuration: {
          file_upload: {
            enabled:
              parsedBody?.chatkit_configuration?.file_upload?.enabled ?? false,
          },
        },
      }),
    });

    const upstreamJson = (await upstreamResponse.json().catch(() => ({}))) as
      | Record<string, unknown>
      | undefined;

    if (!upstreamResponse.ok) {
      const upstreamError = extractUpstreamError(upstreamJson);
      return jsonWithCookie(
        {
          error:
            upstreamError ??
            `Failed to create session: ${upstreamResponse.statusText}`,
          details: upstreamJson ?? {},
        },
        upstreamResponse.status,
        sessionCookie
      );
    }

    const clientSecret = (upstreamJson?.client_secret as string | undefined) ?? null;
    const expiresAfter = (upstreamJson?.expires_after as unknown) ?? null;

    // If OpenAI replied OK but did not send a client_secret, the frontend will hang.
    // So we fail loudly.
    if (!clientSecret) {
      return jsonWithCookie(
        {
          error: "Session created but client_secret missing from response",
          details: upstreamJson ?? {},
        },
        502,
        sessionCookie
      );
    }

    return jsonWithCookie(
      { client_secret: clientSecret, expires_after: expiresAfter },
      200,
      sessionCookie
    );
  } catch (err) {
    return jsonWithCookie({ error: "Unexpected error" }, 500, sessionCookie);
  }
}

export async function GET(): Promise<Response> {
  return methodNotAllowedResponse();
}

function methodNotAllowedResponse(): Response {
  return json({ error: "Method Not Allowed" }, 405);
}

async function resolveUserId(request: Request): Promise<{
  userId: string;
  sessionCookie: string | null;
}> {
  const existing = getCookieValue(
    request.headers.get("cookie"),
    SESSION_COOKIE_NAME
  );
  if (existing) {
    return { userId: existing, sessionCookie: null };
  }

  const generated =
    typeof crypto.randomUUID === "function"
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2);

  return {
    userId: generated,
    sessionCookie: serializeSessionCookie(generated),
  };
}

function getCookieValue(
  cookieHeader: string | null,
  name: string
): string | null {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";");
  for (const cookie of cookies) {
    const [rawName, ...rest] = cookie.split("=");
    if (!rawName || rest.length === 0) continue;
    if (rawName.trim() === name) return rest.join("=").trim();
  }
  return null;
}

function serializeSessionCookie(value: string): string {
  const attributes = [
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(value)}`,
    "Path=/",
    `Max-Age=${SESSION_COOKIE_MAX_AGE}`,
    "HttpOnly",
    "SameSite=Lax",
  ];

  if (process.env.NODE_ENV === "production") {
    attributes.push("Secure");
  }

  return attributes.join("; ");
}

async function safeParseJson<T>(req: Request): Promise<T | null> {
  try {
    const text = await req.text();
    if (!text) return null;
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

function extractUpstreamError(
  payload: Record<string, unknown> | undefined
): string | null {
  if (!payload) return null;

  const error = payload.error;
  if (typeof error === "string") return error;

  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    return (error as { message: string }).message;
  }

  if (typeof payload.message === "string") return payload.message;

  return null;
}

function json(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function jsonWithCookie(
  payload: unknown,
  status: number,
  sessionCookie: string | null
): Response {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (sessionCookie) headers.append("Set-Cookie", sessionCookie);

  return new Response(JSON.stringify(payload), {
    status,
    headers,
  });
}

/**
 * HTTP transport for one private Garmin account.
 *
 * ChatGPT signs in through Auth0. This server accepts only Auth0 access tokens
 * whose signature, issuer, audience, scope, client, and owner are valid.
 * The original high-entropy MCP_BEARER_TOKEN remains a legacy fallback.
 * Never place Garmin credentials or OAuth secrets in this file.
 */
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createPublicKey, timingSafeEqual, verify as verifySignature } from "node:crypto";
import { TokenProvider, resolveApiKey } from "./auth.js";
import { GarminClient } from "./client.js";
import { buildServer } from "./server.js";

const RESOURCE = "https://garmin-personal-mcp.onrender.com";
const ISSUER = "https://dev-wmz5x4sh5cze36tj.us.auth0.com/";
const CLIENT_ID = "3KgBIDZuVnxdBUusB7sv15Nz7Kud3VHL";
const REQUIRED_SCOPE = "garmin:read";
const METADATA_PATH = "/.well-known/oauth-protected-resource";
const JWKS_URL = `${ISSUER}.well-known/jwks.json`;

type Jwk = {
  kid?: string;
  kty?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
};
let keyCache: { keys: Jwk[]; refreshedAt: number } | undefined;

const challenge = `Bearer resource_metadata="${RESOURCE}${METADATA_PATH}", scope="${REQUIRED_SCOPE}"`;

function unauthorized(): Response {
  return new Response("Unauthorized", {
    status: 401,
    headers: { "WWW-Authenticate": challenge, "Cache-Control": "no-store" },
  });
}

function decodeJson(part: string): Record<string, unknown> | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(part)) return undefined;
  const result: unknown = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  if (!result || typeof result !== "object" || Array.isArray(result)) return undefined;
  return result as Record<string, unknown>;
}

async function getSigningKey(kid: string): Promise<Jwk | undefined> {
  if (
    !keyCache ||
    Date.now() - keyCache.refreshedAt > 5 * 60_000 ||
    !keyCache.keys.some((key) => key.kid === kid)
  ) {
    const response = await fetch(JWKS_URL, { signal: AbortSignal.timeout(5000) });
    if (!response.ok) return undefined;
    const body: unknown = await response.json();
    if (!body || typeof body !== "object" || !("keys" in body)) return undefined;
    const keys = (body as { keys: unknown }).keys;
    if (!Array.isArray(keys)) return undefined;
    keyCache = { keys: keys as Jwk[], refreshedAt: Date.now() };
  }
  return keyCache.keys.find(
    (key) =>
      key.kid === kid &&
      key.kty === "RSA" &&
      (key.use === undefined || key.use === "sig") &&
      (key.alg === undefined || key.alg === "RS256") &&
      typeof key.n === "string" &&
      typeof key.e === "string",
  );
}

async function validAuth0Token(token: string): Promise<boolean> {
  // A configured account-owner id is mandatory: no other Auth0 user can read
  // this single Garmin account, even if they can log into the same Auth0 app.
  const allowedSubject = process.env.GARMIN_AUTH0_ALLOWED_SUB;
  if (!allowedSubject || token.length > 16_384) return false;

  try {
    const parts = token.split(".");
    if (parts.length !== 3) return false;
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const header = decodeJson(encodedHeader);
    const claims = decodeJson(encodedPayload);
    if (!header || !claims || !/^[A-Za-z0-9_-]+$/.test(encodedSignature)) return false;
    if (header.alg !== "RS256" || typeof header.kid !== "string") return false;

    const now = Math.floor(Date.now() / 1000);
    const aud = claims.aud;
    const audienceMatches = aud === RESOURCE || (Array.isArray(aud) && aud.includes(RESOURCE));
    if (
      claims.iss !== ISSUER ||
      !audienceMatches ||
      claims.sub !== allowedSubject ||
      claims.azp !== CLIENT_ID ||
      typeof claims.exp !== "number" ||
      claims.exp <= now ||
      (typeof claims.nbf === "number" && claims.nbf > now) ||
      (typeof claims.iat === "number" && claims.iat > now + 60) ||
      typeof claims.scope !== "string" ||
      !claims.scope.split(/\s+/).includes(REQUIRED_SCOPE)
    ) return false;

    const key = await getSigningKey(header.kid);
    if (!key) return false;
    return verifySignature(
      "RSA-SHA256",
      Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
      createPublicKey({ key: { kty: "RSA", n: key.n, e: key.e }, format: "jwk" }),
      Buffer.from(encodedSignature, "base64url"),
    );
  } catch {
    return false;
  }
}

export interface FetchHandlerOptions {
  apiKey?: string;
  apiKeyFile?: string;
  /** Existing static token; kept for compatibility with the original server. */
  bearerToken: string;
  path?: string | string[];
}

export function createFetchHandler(opts: FetchHandlerOptions): (request: Request) => Promise<Response> {
  if (!opts.bearerToken) throw new Error("bearerToken is required for HTTP mode");
  const expected = Buffer.from(opts.bearerToken);
  const paths = new Set(Array.isArray(opts.path) ? opts.path : [opts.path ?? "/mcp"]);
  let garmin: Promise<GarminClient> | undefined;
  const client = () =>
    (garmin ??= resolveApiKey(opts).then((apiKey) => new GarminClient(new TokenProvider({ apiKey }))));

  return async (request) => {
    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === METADATA_PATH || url.pathname === `${METADATA_PATH}/mcp`)) {
      return Response.json({
        resource: RESOURCE,
        authorization_servers: [ISSUER],
        scopes_supported: [REQUIRED_SCOPE],
      }, { headers: { "Cache-Control": "public, max-age=300" } });
    }
    if (!paths.has(url.pathname)) return new Response("Not found", { status: 404 });

    const header = request.headers.get("authorization") ?? "";
    const token = /^Bearer\s+([^\s]+)$/i.exec(header)?.[1] ?? "";
    const given = Buffer.from(token);
    const staticTokenValid =
      given.length === expected.length && timingSafeEqual(given, expected);
    if (!staticTokenValid && !(await validAuth0Token(token))) return unauthorized();

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = buildServer(await client());
    await server.connect(transport);
    try {
      return await transport.handleRequest(request);
    } finally {
      void transport.close().catch(() => {});
    }
  };
}

import { generateRandomString } from "./utils";

// https://developer.x.com/en/docs/authentication/oauth-2-0/authorization-code
export type Scope =
  | "tweet.read"
  | "tweet.write"
  | "tweet.moderate.write"
  | "users.read"
  | "follows.read"
  | "follows.write"
  | "offline.access"
  | "space.read"
  | "mute.read"
  | "mute.write"
  | "like.read"
  | "like.write"
  | "list.read"
  | "list.write"
  | "block.read"
  | "block.write"
  | "bookmark.read"
  | "bookmark.write";

export function buildAuthorizeUrl(
  callbackURL: string,
  scopes: Scope[],
  clientId: string
) {
  const state = generateRandomString(16);
  const challenge = generateRandomString(43);
  let params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: callbackURL,
    scope: scopes.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "plain",
  });

  let url = new URL("https://x.com/i/oauth2/authorize");
  url.search = params.toString();

  return { url, state, challenge };
}

/**
 * public client
 */
export async function requestToken(
  code: string,
  challenge: string,
  clientId: string,
  clientSecret: string,
  callbackURL: string
) {
  const params = new URLSearchParams({
    code,
    grant_type: "authorization_code",
    client_id: clientId,
    redirect_uri: callbackURL,
    code_verifier: challenge,
  });

  const url = new URL("https://api.x.com/2/oauth2/token");
  url.search = params.toString();

  return await fetch(url.toString(), {
    headers: {
      //        "Content-Type": "application/x-www-form-urlencoded",
      // Use deprecated btoa to respect Cloudflare environment
      // https://developers.cloudflare.com/workers/runtime-apis/web-standards/
      Authorization: `Basic ${btoa(`${clientId}:${clientSecret}`)}`,
    },
    method: "POST",
  });
}

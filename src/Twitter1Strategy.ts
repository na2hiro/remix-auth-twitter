import {
  AppLoadContext,
  json,
  redirect,
  SessionStorage,
} from "@remix-run/server-runtime";
import createDebug from "debug";
import {
  AuthenticateOptions,
  Strategy,
  StrategyVerifyCallback,
} from "remix-auth";
import { v4 as uuid } from "uuid";
import hmacSHA1 from "crypto-js/hmac-sha1";
import Base64 from "crypto-js/enc-base64";
import { fixedEncodeURIComponent } from "./utils";

let debug = createDebug("TwitterStrategy");

const requestTokenURL = "https://api.twitter.com/oauth/request_token";
const authorizationURL = "https://api.twitter.com/oauth/authorize";
const authenticationURL = "https://api.twitter.com/oauth/authenticate";
const tokenURL = "https://api.twitter.com/oauth/access_token";

export interface Twitter1StrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  alwaysReauthorize?: boolean;
}

export interface Profile {
  userId: string;
  screenName: string;
}

export interface Twitter1StrategyVerifyParams {
  accessToken: string;
  accessTokenSecret: string;
  profile: Profile;
  context?: AppLoadContext;
}

export const Twitter1StrategyDefaultName = "twitter1";

/**
 * Twitter's OAuth 1.0a login
 *
 * Applications must supply a `verify` callback, for which the function signature is:
 *
 *     function({accessToken, accessTokenSecret, profile}) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * returning the resulting user object to be stored in session.
 *
 * An AuthorizationError should be raised to indicate an authentication failure.
 *
 * Options:
 * - `clientID`           identifies client to service provider
 * - `clientSecret`       secret used to establish ownership of the client identifier
 * - `callbackURL`        URL to which the service provider will redirect the user after obtaining authorization
 * - `alwaysReauthorize`  If set to true, always as app permissions. This was v1 behavior.
 *                        If false, just let them login if they've once accepted the permission. (optional. default: false)
 *
 * @example
 * authenticator.use(new TwitterStrategy(
 *   {
 *     clientID: '123-456-789',
 *     clientSecret: 'shhh-its-a-secret',
 *     callbackURL: 'https://www.example.net/auth/example/callback',
 *   },
 *   async ({ accessToken, accessTokenSecret, profile }) => {
 *     return await User.findOrCreate(profile.id, profile.email, ...);
 *   }
 * ));
 */
export class Twitter1Strategy<User> extends Strategy<
  User,
  Twitter1StrategyVerifyParams
> {
  name = Twitter1StrategyDefaultName;

  protected clientID: string;
  protected clientSecret: string;
  protected callbackURL: string;
  protected alwaysReauthorize: boolean;

  constructor(
    options: Twitter1StrategyOptions,
    verify: StrategyVerifyCallback<User, Twitter1StrategyVerifyParams>
  ) {
    super(verify);
    this.clientID = options.clientID;
    this.clientSecret = options.clientSecret;
    this.callbackURL = options.callbackURL;
    this.alwaysReauthorize = options.alwaysReauthorize || false;
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    debug("Request URL", request.url.toString());
    let url = new URL(request.url);
    let session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );

    let user: User | null = session.get(options.sessionKey) ?? null;

    // User is already authenticated
    if (user) {
      debug("User is authenticated");
      return this.success(user, request, sessionStorage, options);
    }

    let callbackURL = this.getCallbackURL(url);
    debug("Callback URL", callbackURL.toString());

    // Before user navigates to login page: Redirect to login page
    if (url.pathname !== callbackURL.pathname) {
      // Unlike OAuth2, we first hit the request token endpoint
      const { requestToken, callbackConfirmed } = await this.fetchRequestToken(
        callbackURL
      );

      if (!callbackConfirmed) {
        throw json(
          { message: "Callback not confirmed" },
          {
            status: 401,
          }
        );
      }

      // Then let user authorize the app
      throw redirect(this.getAuthURL(requestToken).toString(), {
        headers: {
          "Set-Cookie": await sessionStorage.commitSession(session),
        },
      });
    }

    // Validations of the callback URL params

    const denied = url.searchParams.get("denied");
    if (denied) {
      debug("Denied");
      return await this.failure(
        "Please authorize the app",
        request,
        sessionStorage,
        options
      );
    }
    const oauthToken = url.searchParams.get("oauth_token");
    if (!oauthToken)
      throw json(
        { message: "Missing oauth token from auth response." },
        { status: 400 }
      );
    const oauthVerifier = url.searchParams.get("oauth_verifier");
    if (!oauthVerifier)
      throw json(
        { message: "Missing oauth verifier from auth response." },
        { status: 400 }
      );

    // Get the access token
    let params = new URLSearchParams();
    params.set("oauth_token", oauthToken);
    params.set("oauth_verifier", oauthVerifier);

    let { accessToken, accessTokenSecret, ...profile } =
      await this.fetchAccessTokenAndProfile(params);

    // Verify the user and return it, or redirect
    try {
      user = await this.verify({
        accessToken,
        accessTokenSecret,
        profile,
        context: options.context,
      });
    } catch (error) {
      debug("Failed to verify user", error);
      let message = (error as Error).message;
      return await this.failure(message, request, sessionStorage, options);
    }

    debug("User authenticated");
    return await this.success(user, request, sessionStorage, options);
  }

  private getCallbackURL(url: URL) {
    if (
      this.callbackURL.startsWith("http:") ||
      this.callbackURL.startsWith("https:")
    ) {
      return new URL(this.callbackURL);
    }
    if (this.callbackURL.startsWith("/")) {
      return new URL(this.callbackURL, url);
    }
    return new URL(`${url.protocol}//${this.callbackURL}`);
  }

  private static generateNonce() {
    return uuid();
  }

  private static generateTimestamp() {
    return `${Math.floor(Date.now() / 1000)}`;
  }

  /**
   * Step 1: oauth/request_token
   */
  private async fetchRequestToken(callbackUrl: URL): Promise<{
    requestToken: string;
    requestTokenSecret: string;
    callbackConfirmed: boolean;
  }> {
    const parameters = this.signRequest(
      { oauth_callback: callbackUrl.toString() },
      "GET",
      requestTokenURL
    );
    const url = new URL(requestTokenURL);
    url.search = new URLSearchParams(parameters).toString();
    const urlString = url.toString();
    debug("Fetching request token", urlString);
    let response = await fetch(urlString, {
      method: "GET",
    });

    if (!response.ok) {
      let body = await response.text();
      throw new Response(body, { status: 401 });
    }
    const text = await response.text();
    const body: { [key: string]: string } = {};
    for (const pair of text.split("&")) {
      const [key, value] = pair.split("=");
      body[key] = value;
    }

    return {
      requestToken: body.oauth_token as string,
      requestTokenSecret: body.oauth_token_secret as string,
      callbackConfirmed: body.oauth_callback_confirmed === "true",
    };
  }

  /**
   * Generate signature with HMAC-SHA1 algorithm
   */
  signRequest(
    headers: { [key: string]: string },
    method: "GET" | "POST",
    url: string,
    accessTokenSecret?: string
  ) {
    const params = {
      ...headers,
      oauth_consumer_key: this.clientID,
      oauth_nonce: Twitter1Strategy.generateNonce(),
      oauth_timestamp: Twitter1Strategy.generateTimestamp(),
      oauth_version: "1.0",
      oauth_signature_method: "HMAC-SHA1",
    };
    // Convert to "key=value, key=value" format
    const parameters = Object.entries(params)
      .sort(([k1], [k2]) => k1.localeCompare(k2))
      .map(
        ([key, value]) =>
          `${fixedEncodeURIComponent(key)}=${fixedEncodeURIComponent(value)}`
      )
      .join("&");
    const signature_base = `${method}&${fixedEncodeURIComponent(
      url
    )}&${fixedEncodeURIComponent(parameters)}`;
    const signing_key = `${this.clientSecret}&${accessTokenSecret || ""}`;
    const signed = Base64.stringify(hmacSHA1(signature_base, signing_key));
    return {
      ...params,
      oauth_signature: signed,
      oauth_signature_method: "HMAC-SHA1",
    };
  }

  /**
   * Step 2: Let user authorize
   */
  private getAuthURL(requestToken: string) {
    let params = new URLSearchParams();
    params.set("oauth_token", requestToken);

    let url = new URL(
      this.alwaysReauthorize ? authorizationURL : authenticationURL
    );
    url.search = params.toString();

    return url;
  }

  /**
   * Step 3: Fetch access token to do anything
   */
  private async fetchAccessTokenAndProfile(params: URLSearchParams): Promise<{
    accessToken: string;
    accessTokenSecret: string;
    userId: string;
    screenName: string;
  }> {
    params.set("oauth_consumer_key", this.clientID);

    debug("Fetch access token", tokenURL, params.toString());
    let response = await fetch(tokenURL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    if (!response.ok) {
      let body = await response.text();
      // TODO: ここにくる
      debug("error! " + body);
      throw new Response(body, { status: 401 });
    }

    return await this.extractAccessTokenAndProfile(
      response.clone() as unknown as Response
    );
  }

  protected async extractAccessTokenAndProfile(response: Response): Promise<{
    accessToken: string;
    accessTokenSecret: string;
    userId: string;
    screenName: string;
  }> {
    const text = await response.text();
    const obj: { [key: string]: string } = {};
    for (const pair of text.split("&")) {
      const [key, value] = pair.split("=");
      obj[key] = value;
    }
    return {
      accessToken: obj.oauth_token as string,
      accessTokenSecret: obj.oauth_token_secret as string,
      userId: obj.user_id as string,
      screenName: obj.screen_name as string,
    } as const;
  }
}

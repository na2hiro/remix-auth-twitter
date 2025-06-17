import Base64 from "crypto-js/enc-base64.js";
import hmacSHA1 from "crypto-js/hmac-sha1.js";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { v4 as uuid } from "uuid";
import { redirect } from "./lib/redirect.js";
import { fixedEncodeURIComponent } from "./lib/uri-encoding.js";

const debug = createDebug("TwitterStrategy");

const requestTokenURL = "https://api.x.com/oauth/request_token";
const authorizationURL = "https://api.x.com/oauth/authorize";
const authenticationURL = "https://api.x.com/oauth/authenticate";
const tokenURL = "https://api.x.com/oauth/access_token";

export const Twitter1StrategyDefaultName = "twitter1";

/**
 * Twitter's OAuth 1.0a login (https://developer.x.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens)
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
 * - `consumerKey`        "API Key" under "Consumer Keys", which identifies client to service provider
 * - `clientSecret`       "API Secret" under "Consumer Keys", which is a secret used to establish ownership of the client identifier
 * - `callbackURL`        URL to which the service provider will redirect the user after obtaining authorization
 * - `alwaysReauthorize`  If set to true, always as app permissions. This was v1 behavior.
 *                        If false, just let them login if they've once accepted the permission. (optional. default: false)
 *
 * @example
 * authenticator.use(new Twitter1Strategy(
 *   {
 *     consumerKey: '123-456-789',
 *     consumerSecret: 'shhh-its-a-secret',
 *     callbackURL: 'https://www.example.net/auth/example/callback',
 *   },
 *   async ({ accessToken, accessTokenSecret, profile }) => {
 *     return await User.findOrCreate(profile.id, profile.email, ...);
 *   }
 * ));
 */
export class Twitter1Strategy<User> extends Strategy<
  User,
  Twitter1Strategy.VerifyOptions
> {
  name = Twitter1StrategyDefaultName;

  protected consumerKey: string;
  protected consumerSecret: string;
  protected callbackURL: string;
  protected alwaysReauthorize: boolean;

  constructor(
    protected options: Twitter1Strategy.ConstructorOptions,
    verify: Strategy.VerifyFunction<User, Twitter1Strategy.VerifyOptions>
  ) {
    super(verify);
    this.consumerKey = options.consumerKey;
    this.consumerSecret = options.consumerSecret;
    this.callbackURL = options.callbackURL;
    this.alwaysReauthorize = options.alwaysReauthorize || false;
  }

  async authenticate(request: Request): Promise<User> {
    debug("Request URL", request.url.toString());
    const url = new URL(request.url);

    const callbackURL = this.getCallbackURL(url);
    debug("Callback URL", callbackURL.toString());

    // Before user navigates to login page: Redirect to login page
    if (url.pathname !== callbackURL.pathname) {
      // Unlike OAuth2, we first hit the request token endpoint
      const { requestToken, callbackConfirmed } = await this.fetchRequestToken(
        callbackURL
      );

      if (!callbackConfirmed) {
        throw new Error("Callback not confirmed");
      }

      // Then let user authorize the app
      throw redirect(this.getAuthURL(requestToken).toString());
    }

    // Validations of the callback URL params
    const denied = url.searchParams.get("denied");
    if (denied) {
      debug("Denied");
      throw new Error("Please authorize the app");
    }
    const oauthToken = url.searchParams.get("oauth_token");
    if (!oauthToken)
      throw new ReferenceError("Missing oauth token from auth response.");
    const oauthVerifier = url.searchParams.get("oauth_verifier");
    if (!oauthVerifier)
      throw new ReferenceError("Missing oauth verifier from auth response.");

    // Get the access token
    const params = new URLSearchParams();
    params.set("oauth_token", oauthToken);
    params.set("oauth_verifier", oauthVerifier);

    const { accessToken, accessTokenSecret, ...profile } =
      await this.fetchAccessTokenAndProfile(params);

    // Verify the user and return it
    debug("Verifying the user profile");
    const user = await this.verify({
      accessToken,
      accessTokenSecret,
      profile,
    });

    debug("User authenticated");
    return user;
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
    const response = await fetch(urlString, {
      method: "GET",
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Response(body, { status: 401 });
    }
    const text = await response.text();
    const body: { [key: string]: string } = {};
    for (const pair of text.split("&")) {
      const [key, value] = pair.split("=");
      if (typeof key !== "undefined" && typeof value !== "undefined") {
        body[key] = value;
      }
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
      oauth_consumer_key: this.consumerKey,
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
    const signing_key = `${this.consumerSecret}&${accessTokenSecret || ""}`;
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
    const params = new URLSearchParams();
    params.set("oauth_token", requestToken);

    const url = new URL(
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
    params.set("oauth_consumer_key", this.consumerKey);

    debug("Fetch access token", tokenURL, params.toString());
    const response = await fetch(tokenURL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    if (!response.ok) {
      const body = await response.text();
      debug(`error! ${body}`);
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
      if (typeof key !== "undefined" && typeof value !== "undefined") {
        obj[key] = value;
      }
    }
    return {
      accessToken: obj.oauth_token as string,
      accessTokenSecret: obj.oauth_token_secret as string,
      userId: obj.user_id as string,
      screenName: obj.screen_name as string,
    } as const;
  }
}

export namespace Twitter1Strategy {
  export interface ConstructorOptions {
    consumerKey: string;
    consumerSecret: string;
    callbackURL: string;
    alwaysReauthorize?: boolean;
  }

  export interface Profile {
    userId: string;
    screenName: string;
  }

  export interface VerifyOptions {
    accessToken: string;
    accessTokenSecret: string;
    profile: Profile;
  }
}

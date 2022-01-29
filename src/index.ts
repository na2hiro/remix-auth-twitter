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

const requestTokenURL = new URL("https://api.twitter.com/oauth/request_token");
const authorizationURL = "https://api.twitter.com/oauth/authorize";
const tokenURL = "https://api.twitter.com/oauth/access_token";
const verifyCredentialsURL = new URL(
  "https://api.twitter.com/1.1/account/verify_credentials.json"
);

export interface TwitterExtraParams extends Record<string, string | number> {
  accessTokenSecret: string;
}

export type TwitterProfile = any; // TODO: copy

export interface TwitterStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface TwitterStrategyVerifyParams<Profile extends TwitterProfile> {
  accessToken: string;
  extraParams: TwitterExtraParams;
  profile: Profile;
  context?: AppLoadContext;
}

/**
 * The OAuth 2.0 authentication strategy authenticates requests using the OAuth
 * 2.0 framework.
 *
 * OAuth 2.0 provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Facebook.  Delegating in
 * this manner involves a sequence of events, including redirecting the user to
 * the third-party service for authorization.  Once authorization has been
 * granted, the user is redirected back to the application and an authorization
 * code can be used to obtain credentials.
 *
 * Applications must supply a `verify` callback, for which the function
 * signature is:
 *
 *     function(accessToken, profile) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * returning the resulting user object.
 *
 * An AuthorizationError should be raised to indicate an authentication failure.
 *
 * Options:
 * - `clientID`          identifies client to service provider
 * - `clientSecret`      secret used to establish ownership of the client identifier
 * - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *
 * @example
 * authenticator.use(new OAuth2Strategy(
 *   {
 *     clientID: '123-456-789',
 *     clientSecret: 'shhh-its-a-secret'
 *     callbackURL: 'https://www.example.net/auth/example/callback'
 *   },
 *   async ({ accessToken, profile }) => {
 *     return await User.findOrCreate(...);
 *   }
 * ));
 */
export class TwitterStrategy<
  User,
  Profile extends TwitterProfile
> extends Strategy<User, TwitterStrategyVerifyParams<Profile>> {
  name = "twitter";

  protected clientID: string;
  protected clientSecret: string;
  protected callbackURL: string;

  constructor(
    options: TwitterStrategyOptions,
    verify: StrategyVerifyCallback<User, TwitterStrategyVerifyParams<Profile>>
  ) {
    super(verify);
    this.clientID = options.clientID;
    this.clientSecret = options.clientSecret;
    this.callbackURL = options.callbackURL;
  }

  async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    console.log("AUTHENTICATE!");
    debug("Request URL", request.url);
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
    debug("Callback URL", callbackURL);

    // Before user navigates to login page: Redirect to login page
    if (url.pathname !== callbackURL.pathname) {
      debug("Requesting request token");
      // Unlike OAuth2, we first hit the request token endpoint
      const { requestToken, callbackConfirmed } = await this.fetchRequestToken(
        callbackURL
      );

      if (!callbackConfirmed) {
        throw new Response("Callback not confirmed", {
          status: 401,
        });
      }

      // let state = this.generateState();
      // debug("State", state);
      // session.set(this.sessionStateKey, state);
      throw redirect(this.getAuthorizationURL(requestToken).toString(), {
        headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
      });
    }

    // Validations of the callback URL params

    const oauthToken = url.searchParams.get("oauth_token");
    if (!oauthToken)
      throw json({ message: "Missing oauth token." }, { status: 400 });
    const oauthVerifier = url.searchParams.get("oauth_verifier");
    if (!oauthVerifier)
      throw json({ message: "Missing oauth verifier." }, { status: 400 });

    // Get the access token

    let params = new URLSearchParams();
    params.set("oauth_token", oauthToken);
    params.set("oauth_verifier", oauthVerifier);

    let { accessToken, accessTokenSecret } = await this.fetchAccessToken(
      params
    );

    // Get the profile

    let profile = await this.userProfile(accessToken, accessTokenSecret);

    // Verify the user and return it, or redirect
    try {
      user = await this.verify({
        accessToken,
        extraParams: {
          accessTokenSecret,
        },
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
    console.log({ url: url.toString() });
    let response = await fetch(url.toString(), {
      method: "GET",
    });

    if (!response.ok) {
      try {
        let body = await response.text();
        console.error({ body });
        throw new Response(body, { status: 401 });
      } catch (error) {
        throw new Response((error as Error).message, { status: 401 });
      }
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

  generateAuthHeader(
    url: URL,
    method: "GET" | "POST",
    accessTokenSecret?: string
  ) {
    const parameters = this.signRequest(
      {
        //oauth_callback: this.callbackURL,
        oauth_consumer_key: this.clientID,
        oauth_nonce: TwitterStrategy.generateNonce(),
        oauth_timestamp: TwitterStrategy.generateTimestamp(),
        oauth_version: "1.0",
      },
      method,
      url,
      accessTokenSecret
    );
    return Object.entries(parameters)
      .sort(([k1], [k2]) => k1.localeCompare(k2))
      .map(([key, value]) => `${key}="${fixedEncodeURIComponent(value)}"`)
      .join(", ");
  }

  /**
   * Generate signature with HMAC-SHA1 algorithm
   */
  signRequest(
    headers: { [key: string]: string },
    method: "GET" | "POST",
    url: URL,
    accessTokenSecret?: string
  ) {
    const params = {
      ...headers,
      oauth_consumer_key: this.clientID,
      oauth_nonce: TwitterStrategy.generateNonce(),
      oauth_timestamp: TwitterStrategy.generateTimestamp(),
      oauth_version: "1.0",
      oauth_signature_method: "HMAC-SHA1",
    };
    //Convert to "key=value, key=value" format
    const parameters = Object.entries(params)
      .sort(([k1], [k2]) => k1.localeCompare(k2))
      .map(
        ([key, value]) =>
          `${fixedEncodeURIComponent(key)}=${fixedEncodeURIComponent(value)}`
      )
      .join("&");
    const signature_base = `${method}&${fixedEncodeURIComponent(
      url.toString()
    )}&${fixedEncodeURIComponent(parameters)}`;
    const signing_key = `${this.clientSecret}&${accessTokenSecret || ""}`;
    const signed = Base64.stringify(hmacSHA1(signature_base, signing_key));
    console.log({ signature_base, signing_key, signed });
    return {
      ...params,
      oauth_signature: signed,
      oauth_signature_method: "HMAC-SHA1",
    };
  }

  /**
   * Step 2: Let user authorize
   */
  private getAuthorizationURL(requestToken: string) {
    let params = new URLSearchParams();
    params.set("oauth_token", requestToken);

    let url = new URL(authorizationURL);
    url.search = params.toString();

    return url;
  }

  /**
   * Step 3: Fetch access token to do anything
   */
  private async fetchAccessToken(params: URLSearchParams): Promise<{
    accessToken: string;
    accessTokenSecret: string;
  }> {
    params.set("oauth_consumer_key", this.clientID);

    let response = await fetch(tokenURL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params,
    });

    if (!response.ok) {
      try {
        let body = await response.text();
        debug("error! " + body);
        throw new Response(body, { status: 401 });
      } catch (error) {
        throw new Response((error as Error).message, { status: 401 });
      }
    }

    return await this.getAccessToken(response.clone() as unknown as Response);
  }

  protected async getAccessToken(response: Response): Promise<{
    accessToken: string;
    accessTokenSecret: string;
  }> {
    const text = await response.text();
    const obj: { [key: string]: string } = {};
    for (const pair of text.split("&")) {
      const [key, value] = pair.split("=");
      obj[key] = value;
    }
    const accessToken = obj.oauth_token as string;
    const accessTokenSecret = obj.oauth_token_secret as string;
    return {
      accessToken,
      accessTokenSecret,
    } as const;
  }

  /**
   * Retrieve user profile from service provider.
   *
   * OAuth 2.0-based authentication strategies can override this function in
   * order to load the user's profile from the service provider.  This assists
   * applications (and users of those applications) in the initial registration
   * process by automatically submitting required information.
   */
  // protected
  async userProfile(
    accessToken: string,
    accessTokenSecret: string
  ): Promise<Profile> {
    const url = new URL(verifyCredentialsURL);
    const params = this.signRequest(
      {
        oauth_token: accessToken,
      },
      "GET",
      url,
      accessTokenSecret
    );
    url.search = new URLSearchParams(params).toString();
    console.log(url.toString());
    const response = await fetch(url.toString());
    return await response.json();
  }
}

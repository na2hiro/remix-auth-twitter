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
import { requestToken, buildAuthorizeUrl, Scope } from "./oauth2Api";

let debug = createDebug("TwitterStrategy");

export interface Twitter2StrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
}

export interface Twitter2StrategyVerifyParams {
  accessToken: string;
  expiresIn: number;
  scope: string;
  context?: AppLoadContext;
}

export const Twitter2StrategyDefaultName = "twitter2";

/**
 * Twitter's OAuth 2.0 login (https://developer.twitter.com/en/docs/authentication/oauth-2-0/user-access-token)
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
export class Twitter2Strategy<User> extends Strategy<
  User,
  Twitter2StrategyVerifyParams
> {
  name = Twitter2StrategyDefaultName;

  protected clientID: string;
  protected clientSecret: string;
  protected callbackURL: string;

  constructor(
    options: Twitter2StrategyOptions,
    verify: StrategyVerifyCallback<User, Twitter2StrategyVerifyParams>
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
      // Step 1: Construct an Authorize URL
      const scopes: Scope[] = ["tweet.write", "tweet.read", "users.read"]; // TODO: get

      // Step 2: GET oauth2/authorize
      const { url, state, challenge } = buildAuthorizeUrl(
        this.callbackURL,
        scopes,
        this.clientID
      );
      session.set("auth-twitter_state", state);
      session.set("auth-twitter_challenge", challenge);
      throw redirect(url.toString(), {
        headers: {
          "Set-Cookie": await sessionStorage.commitSession(session),
        },
      });
    }

    // User rejected the app
    const errorFromAuth = url.searchParams.get("error");
    if (errorFromAuth === "access_denied") {
      debug("Denied");
      return await this.failure(
        "Please authorize the app",
        request,
        sessionStorage,
        options
      );
    }
    const code = url.searchParams.get("code");
    if (!code)
      throw json(
        { message: "Missing code from auth response." },
        { status: 400 }
      );
    const state = url.searchParams.get("state");
    if (session.get("auth-twitter_state") !== state)
      throw json({ message: "State doesn't match" }, { status: 400 });

    // Step 3: POST oauth2/token - Access Token
    const response = await requestToken(
      code,
      session.get("auth-twitter_challenge"),
      this.clientID,
      this.clientSecret,
      this.callbackURL
    );

    if (!response.ok) {
      debug("Failed to get access token " + (await response.text()));
      throw json(
        {
          message: "Failed to get access token",
        },
        { status: 400 }
      );
    }
    const body = await response.json();
    debug("access token " + JSON.stringify(body));
    const { expires_in, access_token, scope } = body;

    // Verify the user and return it, or redirect
    try {
      user = await this.verify({
        accessToken: access_token,
        expiresIn: expires_in,
        scope,
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
}

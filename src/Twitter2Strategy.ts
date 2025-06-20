import { Cookie, SetCookie, type SetCookieInit } from "@mjackson/headers";
import {
	OAuth2RequestError,
	type OAuth2Tokens,
	Twitter,
	UnexpectedErrorResponseBodyError,
	UnexpectedResponseError,
	generateCodeVerifier,
	generateState,
} from "arctic";

import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";

const debug = createDebug("Twitter2Strategy");

export const Twitter2StrategyDefaultName = "twitter2";

export {
	OAuth2RequestError,
	UnexpectedResponseError,
	UnexpectedErrorResponseBodyError,
};

/**
 * Twitter's OAuth 2.0 login (https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token)
 *
 * Applications must supply a `verify` callback, for which the function signature is:
 *
 *     function({ request, tokens }) { ... }
 *
 * The verify callback is responsible for finding or creating the user, and
 * returning the resulting user object
 *
 * An AuthorizationError should be raised to indicate an authentication failure.
 *
 * Options:
 * - `clientID`           "Client ID" under "OAuth 2.0 Client ID and Client Secret", which identifies client to service provider
 * - `clientSecret`       "Client Secret" under "OAuth 2.0 Client ID and Client Secret", which is a secret used to establish ownership of the client identifier
 * - `callbackURL`        URL to which the service provider will redirect the user after obtaining authorization
 *                        If false, just let them login if they've once accepted the permission. (optional. default: false)
 *
 * @example
 * authenticator.use(new Twitter2Strategy(
 *   {
 *     clientID: '123-456-789',
 *     clientSecret: 'shhh-its-a-secret',
 *     callbackURL: 'https://www.example.net/auth/example/callback',
 *   },
 *   async ({ request, tokens }) => {
 *     const accessToken = tokens.accessToken();
 *     const me = await (use accessToken to fetch me via /2/users/me for example)
 *     return await User.findOrCreate(, ...);
 *   }
 * ));
 */
export class Twitter2Strategy<User> extends Strategy<
	User,
	Twitter2Strategy.VerifyOptions
> {
	name = Twitter2StrategyDefaultName;

	protected client: Twitter;

	constructor(
		protected options: Twitter2Strategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, Twitter2Strategy.VerifyOptions>,
	) {
		super(verify);

		this.client = new Twitter(
			options.clientID,
			options.clientSecret,
			options.callbackURL.toString(),
		);
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || Twitter2StrategyDefaultName;
		}
		return this.options.cookie?.name ?? Twitter2StrategyDefaultName;
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	override async authenticate(request: Request): Promise<User> {
		debug("Request URL", request.url.toString());
		const url = new URL(request.url);

		const stateUrl = url.searchParams.get("state");
		const error = url.searchParams.get("error");

		if (error) {
			debug("error", error);
			const description = url.searchParams.get("error_description");
			const uri = url.searchParams.get("error_uri");
			throw new OAuth2RequestError(error, description, uri, stateUrl);
		}

		// Before user navigates to login page: Redirect to login page
		if (!stateUrl) {
			debug("No state found in the URL, redirecting to authorization endpoint");
			// Step 1: Construct an Authorize URL
			const state = generateState();
			const challenge = generateCodeVerifier();

			debug("Generated State", state);
			debug("Generated Code Verifier", challenge);

			const url = this.client.createAuthorizationURL(
				state,
				challenge,
				this.options.scopes,
			);

			debug("Authorization URL", url.toString());

			const header = new SetCookie({
				name: this.cookieName,
				value: new URLSearchParams({ state, challenge }).toString(),
				httpOnly: true, // Prevents JavaScript from accessing the cookie
				maxAge: 60 * 10, // 10 minutes
				path: "/", // Allow the cookie to be sent to any path
				sameSite: "Lax", // Prevents it from being sent in cross-site requests
				...this.cookieOptions,
			});

			// Step 2: GET oauth2/authorize
			throw redirect(url.toString(), {
				headers: {
					"Set-Cookie": header.toString(),
				},
			});
		}

		url.searchParams.forEach((value, key) => {
			debug(`URL search param: ${key} = ${value}`);
		});

		const code = url.searchParams.get("code");
		if (!code) throw new ReferenceError("Missing code in the URL");

		const cookie = new Cookie(request.headers.get("cookie") ?? "");
		const params = new URLSearchParams(cookie.get(this.cookieName) ?? "");

		if (!params.has("state")) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (!params.has("challenge")) {
			throw new ReferenceError("Missing challenge/code-verifier on cookie.");
		}

		if (params.get("state") !== stateUrl) {
			debug("state mismatch", stateUrl, params.get("state"));
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		debug("Validating authorization code");
		const tokens = await this.client.validateAuthorizationCode(
			code,
			params.get("challenge") ?? "",
		);

		debug("Verifying the user profile");
		const user = await this.verify({ request, tokens });

		debug("User authenticated");
		return user;
	}
}

export namespace Twitter2Strategy {
	export interface ConstructorOptions {
		/**
		 * The name of the cookie used to keep state and code verifier around.
		 *
		 * The OAuth2 flow requires generating a random state and code verifier, and
		 * then checking that the state matches when the user is redirected back to
		 * the application. This is done to prevent CSRF attacks.
		 *
		 * The state and code verifier are stored in a cookie, and this option
		 * allows you to customize the name of that cookie if needed.
		 * @default "twitter2"
		 */
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });

		/**
		 * This is the Client ID of your application, provided to you by the Identity
		 * Provider you're using to authenticate users.
		 */
		clientID: string;

		/**
		 * This is the Client Secret of your application, provided to you by the
		 * Identity Provider you're using to authenticate users.
		 */
		clientSecret: string;

		/**
		 * The URL of your application where the Identity Provider will redirect the
		 * user after they've logged in or authorized your application.
		 */
		callbackURL: string;

		/**
		 * The scopes you want to request from the Identity Provider, this is a list
		 * of strings that represent the permissions you want to request from the
		 * user.
		 */
		scopes: Scope[];
	}

	export interface VerifyOptions {
		/** The request that triggered the verification flow */
		request: Request;
		/** The OAuth2 tokens retrivied from the identity provider */
		tokens: OAuth2Tokens;
	}

	/**
	 * The scopes that can be requested from Twitter's OAuth 2.0 API.
	 * @see https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code#scopes
	 */
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
		| "bookmark.write"
		| "media.write";
}

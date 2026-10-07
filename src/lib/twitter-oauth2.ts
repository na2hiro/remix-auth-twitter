// Adapted from Arctic 3.7.0 (MIT), copyright 2023 pilcrowOnPaper.
// See THIRD_PARTY_LICENSES.md for the original license.
import * as sha2 from "@oslojs/crypto/sha2";
import * as encoding from "@oslojs/encoding";

const authorizationEndpoint = "https://x.com/i/oauth2/authorize";
const tokenEndpoint = "https://api.x.com/2/oauth2/token";
const tokenRevocationEndpoint = "https://api.x.com/2/oauth2/revoke";

export class OAuth2Tokens {
	constructor(public data: object) {}

	tokenType(): string {
		if ("token_type" in this.data && typeof this.data.token_type === "string") {
			return this.data.token_type;
		}
		throw new Error("Missing or invalid 'token_type' field");
	}

	accessToken(): string {
		if (
			"access_token" in this.data &&
			typeof this.data.access_token === "string"
		) {
			return this.data.access_token;
		}
		throw new Error("Missing or invalid 'access_token' field");
	}

	accessTokenExpiresInSeconds(): number {
		if ("expires_in" in this.data && typeof this.data.expires_in === "number") {
			return this.data.expires_in;
		}
		throw new Error("Missing or invalid 'expires_in' field");
	}

	accessTokenExpiresAt(): Date {
		return new Date(Date.now() + this.accessTokenExpiresInSeconds() * 1000);
	}

	hasRefreshToken(): boolean {
		return (
			"refresh_token" in this.data &&
			typeof this.data.refresh_token === "string"
		);
	}

	refreshToken(): string {
		if (
			"refresh_token" in this.data &&
			typeof this.data.refresh_token === "string"
		) {
			return this.data.refresh_token;
		}
		throw new Error("Missing or invalid 'refresh_token' field");
	}

	hasScopes(): boolean {
		return "scope" in this.data && typeof this.data.scope === "string";
	}

	scopes(): string[] {
		if ("scope" in this.data && typeof this.data.scope === "string") {
			return this.data.scope.split(" ");
		}
		throw new Error("Missing or invalid 'scope' field");
	}

	idToken(): string {
		if ("id_token" in this.data && typeof this.data.id_token === "string") {
			return this.data.id_token;
		}
		throw new Error("Missing or invalid field 'id_token'");
	}
}

export function generateCodeVerifier(): string {
	const randomValues = new Uint8Array(32);
	crypto.getRandomValues(randomValues);
	return encoding.encodeBase64urlNoPadding(randomValues);
}

export function generateState(): string {
	const randomValues = new Uint8Array(32);
	crypto.getRandomValues(randomValues);
	return encoding.encodeBase64urlNoPadding(randomValues);
}

function createS256CodeChallenge(codeVerifier: string): string {
	const bytes = sha2.sha256(new TextEncoder().encode(codeVerifier));
	return encoding.encodeBase64urlNoPadding(bytes);
}

function createOAuth2Request(endpoint: string, body: URLSearchParams): Request {
	const bodyBytes = new TextEncoder().encode(body.toString());
	const request = new Request(endpoint, { method: "POST", body: bodyBytes });
	request.headers.set("Content-Type", "application/x-www-form-urlencoded");
	request.headers.set("Accept", "application/json");
	request.headers.set("User-Agent", "remix-auth-twitter");
	request.headers.set("Content-Length", bodyBytes.byteLength.toString());
	return request;
}

function createOAuth2RequestError(result: object): OAuth2RequestError {
	if (!("error" in result) || typeof result.error !== "string") {
		throw new Error("Invalid error response");
	}
	let description: string | null = null;
	let uri: string | null = null;
	let state: string | null = null;
	if ("error_description" in result) {
		if (typeof result.error_description !== "string")
			throw new Error("Invalid data");
		description = result.error_description;
	}
	if ("error_uri" in result) {
		if (typeof result.error_uri !== "string") throw new Error("Invalid data");
		uri = result.error_uri;
	}
	if ("state" in result) {
		if (typeof result.state !== "string") throw new Error("Invalid data");
		state = result.state;
	}
	return new OAuth2RequestError(result.error, description, uri, state);
}

export class ArcticFetchError extends Error {
	constructor(cause: unknown) {
		super("Failed to send request", { cause });
	}
}

export class OAuth2RequestError extends Error {
	constructor(
		public code: string,
		public description: string | null,
		public uri: string | null,
		public state: string | null,
	) {
		super(`OAuth request error: ${code}`);
	}
}

export class UnexpectedResponseError extends Error {
	constructor(public status: number) {
		super("Unexpected error response");
	}
}

export class UnexpectedErrorResponseBodyError extends Error {
	constructor(
		public status: number,
		public data: unknown,
	) {
		super("Unexpected error response body");
	}
}

function sendRequest(request: Request, revoke: true): Promise<undefined>;
function sendRequest(request: Request, revoke: false): Promise<OAuth2Tokens>;
async function sendRequest(
	request: Request,
	revoke: boolean,
): Promise<OAuth2Tokens | undefined> {
	let response: Response;
	try {
		response = await fetch(request);
	} catch (cause) {
		throw new ArcticFetchError(cause);
	}

	if (response.status === 400 || response.status === 401) {
		let data: unknown;
		try {
			data = await response.json();
		} catch {
			if (revoke)
				throw new UnexpectedErrorResponseBodyError(response.status, null);
			throw new UnexpectedResponseError(response.status);
		}
		if (typeof data !== "object" || data === null) {
			throw new UnexpectedErrorResponseBodyError(response.status, data);
		}
		let error: OAuth2RequestError;
		try {
			error = createOAuth2RequestError(data);
		} catch {
			throw new UnexpectedErrorResponseBodyError(response.status, data);
		}
		throw error;
	}

	if (response.status === 200) {
		if (revoke) {
			if (response.body !== null) await response.body.cancel();
			return;
		}
		let data: unknown;
		try {
			data = await response.json();
		} catch {
			throw new UnexpectedResponseError(response.status);
		}
		if (typeof data !== "object" || data === null) {
			throw new UnexpectedErrorResponseBodyError(response.status, data);
		}
		return new OAuth2Tokens(data);
	}

	if (response.body !== null) await response.body.cancel();
	throw new UnexpectedResponseError(response.status);
}

export class Twitter {
	constructor(
		private clientId: string,
		private clientSecret: string | null,
		private redirectURI: string,
	) {}

	createAuthorizationURL(
		state: string,
		codeVerifier: string,
		scopes: string[],
	): URL {
		const url = new URL(authorizationEndpoint);
		url.searchParams.set("response_type", "code");
		url.searchParams.set("client_id", this.clientId);
		url.searchParams.set("redirect_uri", this.redirectURI);
		url.searchParams.set("state", state);
		url.searchParams.set("code_challenge_method", "S256");
		url.searchParams.set(
			"code_challenge",
			createS256CodeChallenge(codeVerifier),
		);
		if (scopes.length > 0) url.searchParams.set("scope", scopes.join(" "));
		return url;
	}

	async validateAuthorizationCode(
		code: string,
		codeVerifier: string,
	): Promise<OAuth2Tokens> {
		const body = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: this.redirectURI,
			code_verifier: codeVerifier,
		});
		return await sendRequest(this.createRequest(tokenEndpoint, body), false);
	}

	async refreshAccessToken(refreshToken: string): Promise<OAuth2Tokens> {
		const body = new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
		});
		return await sendRequest(this.createRequest(tokenEndpoint, body), false);
	}

	async revokeToken(token: string): Promise<void> {
		const body = new URLSearchParams({ token });
		await sendRequest(this.createRequest(tokenRevocationEndpoint, body), true);
	}

	private createRequest(endpoint: string, body: URLSearchParams): Request {
		if (this.clientSecret === null) body.set("client_id", this.clientId);
		const request = createOAuth2Request(endpoint, body);
		if (this.clientSecret !== null) {
			const bytes = new TextEncoder().encode(
				`${this.clientId}:${this.clientSecret}`,
			);
			request.headers.set(
				"Authorization",
				`Basic ${encoding.encodeBase64(bytes)}`,
			);
		}
		return request;
	}
}

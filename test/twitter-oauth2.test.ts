import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	test,
} from "bun:test";
import { createHash } from "node:crypto";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import {
	OAuth2RequestError,
	Twitter,
	UnexpectedErrorResponseBodyError,
	UnexpectedResponseError,
	generateCodeVerifier,
	generateState,
} from "../src/lib/twitter-oauth2";

const tokenEndpoint = "https://api.twitter.com/2/oauth2/token";
const revokeEndpoint = "https://api.twitter.com/2/oauth2/revoke";
const server = setupServer();

describe("local Twitter OAuth 2.0 client", () => {
	beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
	afterEach(() => server.resetHandlers());
	afterAll(() => server.close());

	test("creates an authorization URL with a SHA-256 PKCE challenge", () => {
		const client = new Twitter(
			"client-id",
			"client-secret",
			"https://example.com/callback",
		);
		const verifier = "fixed-code-verifier";
		const expectedChallenge = createHash("sha256")
			.update(verifier)
			.digest("base64url");
		const url = client.createAuthorizationURL("state-value", verifier, [
			"users.read",
			"tweet.read",
		]);

		expect(url.origin).toBe("https://twitter.com");
		expect(url.pathname).toBe("/i/oauth2/authorize");
		expect(url.searchParams.get("response_type")).toBe("code");
		expect(url.searchParams.get("redirect_uri")).toBe(
			"https://example.com/callback",
		);
		expect(url.searchParams.get("state")).toBe("state-value");
		expect(url.searchParams.get("code_challenge_method")).toBe("S256");
		expect(url.searchParams.get("code_challenge")).toBe(expectedChallenge);
		expect(url.searchParams.get("scope")).toBe("users.read tweet.read");
	});

	test("generates distinct URL-safe state and code verifiers", () => {
		const state = generateState();
		const verifier = generateCodeVerifier();
		expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
		expect(state).not.toBe(verifier);
	});

	test("exchanges a code using Basic auth and preserves token methods", async () => {
		server.use(
			http.post(tokenEndpoint, async ({ request }) => {
				expect(request.headers.get("authorization")).toBe(
					"Basic Y2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=",
				);
				expect(request.headers.get("content-type")).toBe(
					"application/x-www-form-urlencoded",
				);
				const body = new URLSearchParams(await request.text());
				expect(body.get("grant_type")).toBe("authorization_code");
				expect(body.get("code")).toBe("auth-code");
				expect(body.get("code_verifier")).toBe("fixed-code-verifier");
				expect(body.get("redirect_uri")).toBe("https://example.com/callback");
				expect(body.has("client_id")).toBe(false);
				return HttpResponse.json({
					access_token: "access-token",
					token_type: "Bearer",
					expires_in: 3600,
					refresh_token: "refresh-token",
					scope: "users.read tweet.read",
				});
			}),
		);

		const client = new Twitter(
			"client-id",
			"client-secret",
			"https://example.com/callback",
		);
		const tokens = await client.validateAuthorizationCode(
			"auth-code",
			"fixed-code-verifier",
		);
		expect(tokens.accessToken()).toBe("access-token");
		expect(tokens.tokenType()).toBe("Bearer");
		expect(tokens.accessTokenExpiresInSeconds()).toBe(3600);
		expect(tokens.hasRefreshToken()).toBe(true);
		expect(tokens.refreshToken()).toBe("refresh-token");
		expect(tokens.hasScopes()).toBe(true);
		expect(tokens.scopes()).toEqual(["users.read", "tweet.read"]);
	});

	test("keeps OAuth error response fields", async () => {
		server.use(
			http.post(tokenEndpoint, () =>
				HttpResponse.json(
					{
						error: "invalid_grant",
						error_description: "Expired code",
						state: "state-value",
					},
					{ status: 400 },
				),
			),
		);
		const client = new Twitter(
			"client-id",
			"client-secret",
			"https://example.com/callback",
		);
		try {
			await client.validateAuthorizationCode("expired", "verifier");
			throw new Error("Expected the token request to fail");
		} catch (error) {
			expect(error).toBeInstanceOf(OAuth2RequestError);
			const requestError = error as OAuth2RequestError;
			expect(requestError.code).toBe("invalid_grant");
			expect(requestError.description).toBe("Expired code");
			expect(requestError.state).toBe("state-value");
		}
	});

	test("distinguishes malformed and unexpected token responses", async () => {
		const client = new Twitter(
			"client-id",
			"client-secret",
			"https://example.com/callback",
		);
		server.use(
			http.post(tokenEndpoint, () =>
				HttpResponse.json({ error: 42 }, { status: 400 }),
			),
		);
		await expect(
			client.validateAuthorizationCode("code", "verifier"),
		).rejects.toBeInstanceOf(UnexpectedErrorResponseBodyError);

		server.use(
			http.post(tokenEndpoint, () => new HttpResponse(null, { status: 503 })),
		);
		await expect(
			client.validateAuthorizationCode("code", "verifier"),
		).rejects.toMatchObject({
			status: 503,
		});
		await expect(
			client.validateAuthorizationCode("code", "verifier"),
		).rejects.toBeInstanceOf(UnexpectedResponseError);
	});

	test("refreshes and revokes tokens", async () => {
		server.use(
			http.post(tokenEndpoint, async ({ request }) => {
				const body = new URLSearchParams(await request.text());
				expect(body.get("grant_type")).toBe("refresh_token");
				expect(body.get("refresh_token")).toBe("old-refresh-token");
				return HttpResponse.json({ access_token: "new-access-token" });
			}),
			http.post(revokeEndpoint, async ({ request }) => {
				const body = new URLSearchParams(await request.text());
				expect(body.get("token")).toBe("old-refresh-token");
				return new HttpResponse(null, { status: 200 });
			}),
		);
		const client = new Twitter(
			"client-id",
			"client-secret",
			"https://example.com/callback",
		);
		const tokens = await client.refreshAccessToken("old-refresh-token");
		expect(tokens.accessToken()).toBe("new-access-token");
		await client.revokeToken("old-refresh-token");
	});
});

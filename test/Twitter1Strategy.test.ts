import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	mock,
	test,
} from "bun:test";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { Twitter1Strategy } from "../src";
import { catchResponse } from "./helper";

const server = setupServer(
	// Mock request token endpoint
	http.get("https://api.x.com/oauth/request_token", async () => {
		return new HttpResponse(
			"oauth_token=mock_request_token&oauth_token_secret=mock_request_token_secret&oauth_callback_confirmed=true",
			{
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
			},
		);
	}),
	// Mock access token endpoint
	http.post("https://api.x.com/oauth/access_token", async () => {
		return new HttpResponse(
			"oauth_token=mock_access_token&oauth_token_secret=mock_access_token_secret&user_id=123456&screen_name=testuser",
			{
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
			},
		);
	}),
);

describe(Twitter1Strategy.name, () => {
	const verify = mock();

	const options = Object.freeze({
		consumerKey: "MY_CONSUMER_KEY",
		consumerSecret: "MY_CONSUMER_SECRET",
		callbackURL: "https://example.com/callback",
	} satisfies Twitter1Strategy.ConstructorOptions);

	interface User {
		id: string;
	}

	beforeAll(() => {
		server.listen();
	});

	afterEach(() => {
		server.resetHandlers();
	});

	afterAll(() => {
		server.close();
	});

	test("should have the name `twitter1`", () => {
		const strategy = new Twitter1Strategy<User>(options, verify);
		expect(strategy.name).toBe("twitter1");
	});

	test("redirects to authorization url if pathname is not the callback url", async () => {
		const strategy = new Twitter1Strategy<User>(options, verify);

		const request = new Request("https://remix.auth/login");

		const response = await catchResponse(strategy.authenticate(request));

		// biome-ignore lint/style/noNonNullAssertion: This is a test
		const redirect = new URL(response.headers.get("location")!);

		expect(redirect.pathname).toBe("/oauth/authenticate");
		expect(redirect.searchParams.get("oauth_token")).toBe("mock_request_token");
	});

	test("throws if the request token response doesn't confirm callback", async () => {
		// Override the default mock response for this test
		server.use(
			http.get("https://api.x.com/oauth/request_token", async () => {
				return new HttpResponse(
					"oauth_token=mock_request_token&oauth_token_secret=mock_request_token_secret&oauth_callback_confirmed=false",
					{
						headers: { "Content-Type": "application/x-www-form-urlencoded" },
					},
				);
			}),
		);

		const strategy = new Twitter1Strategy<User>(options, verify);
		const request = new Request("https://remix.auth/login");

		expect(strategy.authenticate(request)).rejects.toThrow(
			"Callback not confirmed",
		);
	});

	test("throws if denied parameter is present in callback url", () => {
		const strategy = new Twitter1Strategy<User>(options, verify);

		const request = new Request("https://example.com/callback?denied=true");

		expect(strategy.authenticate(request)).rejects.toThrow(
			"Please authorize the app",
		);
	});

	test("throws if oauth_token is missing from callback url", () => {
		const strategy = new Twitter1Strategy<User>(options, verify);

		const request = new Request(
			"https://example.com/callback?oauth_verifier=12345",
		);

		expect(strategy.authenticate(request)).rejects.toThrow(
			"Missing oauth token from auth response.",
		);
	});

	test("throws if oauth_verifier is missing from callback url", () => {
		const strategy = new Twitter1Strategy<User>(options, verify);

		const request = new Request(
			"https://example.com/callback?oauth_token=mock_request_token",
		);

		expect(strategy.authenticate(request)).rejects.toThrow(
			"Missing oauth verifier from auth response.",
		);
	});

	test("calls verify with tokens and profile on successful callback", async () => {
		const strategy = new Twitter1Strategy<User>(options, verify);
		verify.mockResolvedValueOnce({ id: "123" });

		const request = new Request(
			"https://example.com/callback?oauth_token=mock_request_token&oauth_verifier=12345",
		);

		await strategy.authenticate(request);

		expect(verify).toHaveBeenCalled();
		expect(verify).toHaveBeenCalledWith({
			accessToken: "mock_access_token",
			accessTokenSecret: "mock_access_token_secret",
			profile: {
				userId: "123456",
				screenName: "testuser",
			},
		});
	});

	test("returns the result of verify", async () => {
		const user = { id: "123" };
		verify.mockResolvedValueOnce(user);

		const strategy = new Twitter1Strategy<User>(options, verify);

		const request = new Request(
			"https://example.com/callback?oauth_token=mock_request_token&oauth_verifier=12345",
		);

		const result = await strategy.authenticate(request);
		expect(result).toEqual(user);
	});

	test("uses authorizationURL if alwaysReauthorize is true", async () => {
		const strategyWithReauthorize = new Twitter1Strategy<User>(
			{ ...options, alwaysReauthorize: true },
			verify,
		);

		const request = new Request("https://remix.auth/login");

		const response = await catchResponse(
			strategyWithReauthorize.authenticate(request),
		);

		// biome-ignore lint/style/noNonNullAssertion: This is a test
		const redirect = new URL(response.headers.get("location")!);

		expect(redirect.hostname).toBe("api.x.com");
		expect(redirect.pathname).toBe("/oauth/authorize");
	});
});

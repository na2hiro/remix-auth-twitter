import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  mock,
  test,
} from "bun:test";
import { Cookie, SetCookie } from "@mjackson/headers";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { Twitter2Strategy } from "../src";
import { catchResponse } from "./helper";

const server = setupServer(
  http.post("https://api.twitter.com/2/oauth2/token", async () => {
    return HttpResponse.json({
      access_token: "mocked_access_token",
      expires_in: 3600,
      refresh_token: "mocked_refresh_token",
      scope: ["users.read"].join(" "),
      token_type: "Bearer",
    });
  })
);

describe(Twitter2Strategy.name, () => {
  const verify = mock();

  const options = Object.freeze({
    clientID: "MY_CLIENT_ID",
    clientSecret: "MY_CLIENT_SECRET",
    callbackURL: "https://example.com/callback",
    scopes: ["users.read"],
  } satisfies Twitter2Strategy.ConstructorOptions);

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

  test("should have the name `twitter2`", () => {
    const strategy = new Twitter2Strategy<User>(options, verify);
    expect(strategy.name).toBe("twitter2");
  });

  test("redirects to authorization url if there's no state", async () => {
    const strategy = new Twitter2Strategy<User>(options, verify);

    const request = new Request("https://remix.auth/login");

    const response = await catchResponse(strategy.authenticate(request));

    // biome-ignore lint/style/noNonNullAssertion: This is a test
    const redirect = new URL(response.headers.get("location")!);

    const setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");
    const params = new URLSearchParams(setCookie.value);

    expect(redirect.pathname).toBe("/i/oauth2/authorize");
    expect(redirect.searchParams.get("response_type")).toBe("code");
    expect(redirect.searchParams.get("client_id")).toBe(options.clientID);
    expect(redirect.searchParams.get("redirect_uri")).toBe(options.callbackURL);
    expect(redirect.searchParams.has("state")).toBeTruthy();
    expect(redirect.searchParams.get("scope")).toBe(options.scopes.join(" "));

    expect(params.get("state")).toBe(redirect.searchParams.get("state"));
  });
  test("throws if there's no state in the session", () => {
    const strategy = new Twitter2Strategy<User>(options, verify);

    const request = new Request(
      "https://example.com/callback?state=random-state&code=random-code"
    );

    expect(strategy.authenticate(request)).rejects.toThrowError(
      new ReferenceError("Missing state on cookie.")
    );
  });
  test("throws if the state in the url doesn't match the state in the session", async () => {
    const strategy = new Twitter2Strategy<User>(options, verify);
    const cookie = new Cookie();
    cookie.set(
      "twitter2",
      new URLSearchParams({
        state: "random-state",
        challenge: "random-challenge",
      }).toString()
    );

    const request = new Request(
      "https://example.com/callback?state=another-state&code=random-code",
      { headers: { cookie: cookie.toString() } }
    );

    expect(strategy.authenticate(request)).rejects.toThrowError(
      new RangeError("State in URL doesn't match state in cookie.")
    );
  });
  test("calls verify with the tokens and request", async () => {
    const strategy = new Twitter2Strategy<User>(options, verify);
    verify.mockResolvedValueOnce({ id: "123" });

    const cookie = new Cookie();
    cookie.set(
      "twitter2",
      new URLSearchParams({
        state: "random-state",
        challenge: "random-challenge",
      }).toString()
    );

    const request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      { headers: { cookie: cookie.toString() } }
    );

    await strategy.authenticate(request);

    expect(verify).toHaveBeenCalled();
    expect(verify).toHaveBeenCalledWith({
      request,
      tokens: expect.objectContaining({
        accessToken: expect.any(Function),
      }),
    });
  });

  test("returns the result of verify", async () => {
    const user = { id: "123" };
    verify.mockResolvedValueOnce(user);

    const strategy = new Twitter2Strategy<User>(options, verify);

    const cookie = new Cookie();
    cookie.set(
      "twitter2",
      new URLSearchParams({
        state: "random-state",
        challenge: "random-challenge",
      }).toString()
    );

    const request = new Request(
      "https://example.com/callback?state=random-state&code=random-code",
      { headers: { cookie: cookie.toString() } }
    );

    const result = await strategy.authenticate(request);
    expect(result).toEqual(user);
  });
});

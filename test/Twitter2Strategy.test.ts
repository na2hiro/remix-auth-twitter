import { Request, Response, createCookieSessionStorage } from "@remix-run/node";
import fetchMock, { enableFetchMocks } from "jest-fetch-mock";

import { Twitter2Strategy, Twitter2StrategyOptions, Twitter2StrategyVerifyParams } from "../src";
import { assertResponse } from "./testUtils";

jest.mock("../src/utils");

enableFetchMocks();

function fakeFetchUserName(accessToken: string) {
  return "na2hiro";
}

const OPTIONS = {
  sessionKey: "user",
  sessionErrorKey: "error",
  sessionStrategyKey: "strategy",
  name: "twitter2",
};

describe(Twitter2Strategy, () => {
  let verify = jest.fn();
  let sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });
  Date.now = jest.fn(() => 1_234_567_890_123);

  let options = Object.freeze({
    clientID: "MY_CLIENT_ID",
    clientSecret: "MY_CLIENT_SECRET",
    callbackURL: "https://example.com/callback",
    scopes: ["tweet.write", "tweet.read", "users.read"],
  } satisfies Twitter2StrategyOptions);

  interface User {
    id: number;
  }

  beforeEach(() => {
    jest.resetAllMocks();
    fetchMock.resetMocks();
  });

  test("should have the name `twitter2`", () => {
    let strategy = new Twitter2Strategy<User>(options, verify);
    expect(strategy.name).toBe("twitter2");
  });

  test("if user is already in the session redirect to `/`", async () => {
    let strategy = new Twitter2Strategy<User>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("user", { id: 123 });

    let request = new Request("https://example.com/login", {
      headers: { cookie: await sessionStorage.commitSession(session) },
    });

    let user = await strategy.authenticate(request, sessionStorage, OPTIONS);

    expect(user).toEqual({ id: 123 });
  });

  test("if user is already in the session and successRedirect is set throw a redirect", async () => {
    let strategy = new Twitter2Strategy<User>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("user", { id: 123 } satisfies User);

    let request = new Request("https://example.com/login", {
      headers: { cookie: await sessionStorage.commitSession(session) },
    });

    try {
      await strategy.authenticate(request, sessionStorage, {
        ...OPTIONS,
        successRedirect: "/dashboard",
      });
    } catch (error) {
      assertResponse(error);
      expect(error.headers.get("Location")).toBe("/dashboard");
    }
  });

  test("should redirect to authorization if request is not the callback", async () => {
    let strategy = new Twitter2Strategy<User>(options, verify);

    let request = new Request("https://example.com/login");

    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      assertResponse(error);

      expect(fetchMock.mock.calls).toHaveLength(0);

      let redirect = error.headers.get("Location");
      expect(redirect).toMatchInlineSnapshot(
        `"https://x.com/i/oauth2/authorize?response_type=code&client_id=MY_CLIENT_ID&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=tweet.write+tweet.read+users.read&state=MOCKED_RANDOM_CHARS_16&code_challenge=MOCKED_RANDOM_CHARS_43&code_challenge_method=plain"`
      );
    }
  });

  test("should fail if user rejected the app", async () => {
    let strategy = new Twitter2Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?error=access_denied"
    );
    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      assertResponse(error);
      expect(error.status).toEqual(401);
      expect(await error.json()).toEqual({
        message: "Please authorize the app",
      });
    }
  });

  test("should throw if `error` is on the callback URL params", async () => {
    let strategy = new Twitter2Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?error=invalid_scope&oauth_verifier=VERIFIER"
    );
    //
    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      assertResponse(error);
      expect(error.status).toEqual(400);
      expect(await error.json()).toEqual({
        message: "Error from auth response: invalid_scope",
      });
    }
  });

  test("should throw if `code` is not on the callback URL params", async () => {
    let strategy = new Twitter2Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?codeXXXX=TOKEN&oauth_verifier=VERIFIER"
    );
    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      assertResponse(error);
      expect(error.status).toEqual(400);
      expect(await error.json()).toEqual({
        message: "Missing code from auth response.",
      });
    }
  });
  test("should throw if state doesn't match", async () => {
    fetchMock.mockResponse(async (req) => {
      const url = new URL(req.url);
      url.search = "";
      switch (url.toString()) {
        case "https://api.x.com/2/oauth2/token":
          return {
            body: JSON.stringify({
              token_type: "bearer",
              expires_in: 7200,
              access_token: "sth",
              scope: "tweet.write",
            }),
            init: {
              status: 200,
            },
          };
      }
      fail("unknown fetch: " + req.url);
    });

    let strategy = new Twitter2Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?code=CODE&state=STATE"
    );
    const session = await sessionStorage.getSession();
    session.set("auth-twitter_state", "ANOTHER_STATE");
    request.headers.set("Cookie", await sessionStorage.commitSession(session));

    verify.mockImplementationOnce(
      ({ accessToken, expiresIn, scope, context }) => {
        return {
          userName: fakeFetchUserName(accessToken),
        };
      }
    );

    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      assertResponse(error);
      expect(error.status).toEqual(400);
      expect(await error.json()).toEqual({
        message: "State doesn't match",
      });
    }
  });
  test("should return access token", async () => {
    fetchMock.mockResponse(async (req) => {
      const url = new URL(req.url);
      url.search = "";
      switch (url.toString()) {
        case "https://api.x.com/2/oauth2/token":
          return {
            body: JSON.stringify({
              token_type: "bearer",
              expires_in: 7200,
              access_token: "sth",
              refresh_token: "refresh",
              scope: "tweet.write",
            }),
            init: {
              status: 200,
            },
          };
      }
      fail("unknown fetch: " + req.url);
    });

    let strategy = new Twitter2Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?code=TOKEN&state=STATE"
    );

    verify.mockImplementationOnce(
      ({ accessToken, refreshToken, expiresIn, scope, context }) => {
        return {
          userName: fakeFetchUserName(accessToken),
        };
      }
    );
    const session = await sessionStorage.getSession();
    session.set("auth-twitter_state", "STATE");
    request.headers.set("Cookie", await sessionStorage.commitSession(session));

    const user = await strategy.authenticate(request, sessionStorage, OPTIONS);

    expect(user).toEqual({
      userName: "na2hiro",
    });

    expect(fetchMock.mock.calls[0][0]).toMatchInlineSnapshot(
      `"https://api.x.com/2/oauth2/token?code=TOKEN&grant_type=authorization_code&client_id=MY_CLIENT_ID&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&code_verifier=undefined"`
    );

    expect(verify).toHaveBeenLastCalledWith({
      accessToken: "sth",
      refreshToken: "refresh",
      context: undefined,
      expiresIn: 7200,
      scope: "tweet.write",
    } as Twitter2StrategyVerifyParams);
  });

  test("should fail if verify throws Error", async () => {
    fetchMock.mockResponse(async (req) => {
      const url = new URL(req.url);
      url.search = "";
      switch (url.toString()) {
        case "https://api.x.com/2/oauth2/token":
          return {
            body: JSON.stringify({
              access_token: "TOKEN",
              expires_in: 7200,
              scope: "tweet.read",
            }),
            init: {
              status: 200,
            },
          };
      }
      fail("unknown fetch: " + req.url);
    });

    let strategy = new Twitter2Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?code=TOKEN&state=STATE"
    );

    verify.mockImplementationOnce(() => {
      throw new Error("Nah you're banned, go away.");
    });
    const session = await sessionStorage.getSession();
    session.set("auth-twitter_state", "STATE");
    request.headers.set("Cookie", await sessionStorage.commitSession(session));

    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should have thrown");
    } catch (error) {
      assertResponse(error);
      expect(await error.json()).toEqual({
        message: "Nah you're banned, go away.",
      });
      expect(error.status).toEqual(401);
    }
  });
});

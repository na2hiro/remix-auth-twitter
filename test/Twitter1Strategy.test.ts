import { createCookieSessionStorage } from "@remix-run/node";
import fetchMock, { enableFetchMocks } from "jest-fetch-mock";

import {
  Profile,
  Twitter1Strategy,
  Twitter1StrategyVerifyParams,
} from "../src";

const OPTIONS = {
  sessionKey: "user",
  sessionErrorKey: "error",
  sessionStrategyKey: "strategy",
  name: "twitter1",
};

enableFetchMocks();

describe(Twitter1Strategy, () => {
  let verify = jest.fn();
  let sessionStorage = createCookieSessionStorage({
    cookie: { secrets: ["s3cr3t"] },
  });
  Date.now = jest.fn(() => 1_234_567_890_123);

  let options = Object.freeze({
    clientID: "MY_CLIENT_ID",
    clientSecret: "MY_CLIENT_SECRET",
    callbackURL: "https://example.com/callback",
    includeEmail: true,
  });

  interface User {
    id: number;
  }

  beforeEach(() => {
    (Twitter1Strategy as any).generateNonce = () => "abcdefg";
    jest.resetAllMocks();
    fetchMock.resetMocks();
  });

  test("should have the name `twitter`", () => {
    let strategy = new Twitter1Strategy<User>(options, verify);
    expect(strategy.name).toBe("twitter1");
  });

  test("if user is already in the session redirect to `/`", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("user", { id: 123 });

    let request = new Request("https://example.com/login", {
      headers: { cookie: await sessionStorage.commitSession(session) },
    });

    let user = await strategy.authenticate(request, sessionStorage, OPTIONS);

    expect(user).toEqual({ id: 123 });
  });

  test("if user is already in the session and successRedirect is set throw a redirect", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);

    let session = await sessionStorage.getSession();
    session.set("user", { id: 123 } as User);

    let request = new Request("https://example.com/login", {
      headers: { cookie: await sessionStorage.commitSession(session) },
    });

    try {
      await strategy.authenticate(request, sessionStorage, {
        ...OPTIONS,
        successRedirect: "/dashboard",
      });
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      expect(error.headers.get("Location")).toBe("/dashboard");
    }
  });

  test("should throw if callback is not confirmed", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);

    let request = new Request("https://example.com/login");

    fetchMock.mockIf(/oauth\/request_token/, async (req) => {
      return {
        body: "oauth_token=REQUEST_TOKEN&oauth_token_secret=REQUEST_TOKEN_SECRET&oauth_callback_confirmed=false",
        init: { status: 200 },
      };
    });

    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("should throw Response");
    } catch (error) {
      if (!(error instanceof Response)) throw error;

      expect(fetchMock.mock.calls[0][0]).toMatchInlineSnapshot(
        `"https://api.twitter.com/oauth/request_token?oauth_callback=https%3A%2F%2Fexample.com%2Fcallback&oauth_consumer_key=MY_CLIENT_ID&oauth_nonce=abcdefg&oauth_timestamp=NaN&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_signature=1X41i0CFd3rGyZCbyb%2BH5WPMbts%3D"`
      );

      expect(error.status).toBe(401);
      expect(await error.json()).toEqual({ message: "Callback not confirmed" });
    }
  });

  test("should redirect to authorization if request is not the callback", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);

    let request = new Request("https://example.com/login");

    fetchMock.mockResponse(async (req) => {
      const url = new URL(req.url);
      url.search = "";
      switch (url.toString()) {
        case "https://api.twitter.com/oauth/request_token":
          return {
            body: "oauth_token=REQUEST_TOKEN&oauth_token_secret=REQUEST_TOKEN_SECRET&oauth_callback_confirmed=true",
            init: {
              status: 200,
            },
          };
      }
      fail("unknown fetch: " + req.url);
    });

    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      if (!(error instanceof Response)) throw error;

      expect(fetchMock.mock.calls[0][0]).toMatchInlineSnapshot(
        `"https://api.twitter.com/oauth/request_token?oauth_callback=https%3A%2F%2Fexample.com%2Fcallback&oauth_consumer_key=MY_CLIENT_ID&oauth_nonce=abcdefg&oauth_timestamp=NaN&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_signature=1X41i0CFd3rGyZCbyb%2BH5WPMbts%3D"`
      );

      let redirect = error.headers.get("Location");
      expect(redirect).toMatchInlineSnapshot(
        `"https://api.twitter.com/oauth/authenticate?oauth_token=REQUEST_TOKEN"`
      );
    }
  });

  test("should fail if `denied` is on the callback URL params (user rejected the app)", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);
    let request = new Request("https://example.com/callback?denied=ABC-123");
    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      expect(error.status).toEqual(401);
      expect(await error.json()).toEqual({
        message: "Please authorize the app",
      });
    }
  });

  test("should throw if `oauth_token` is not on the callback URL params", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?oauth_tokenXXXX=TOKEN&oauth_verifier=VERIFIER"
    );
    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      expect(error.status).toEqual(400);
      expect(await error.json()).toEqual({
        message: "Missing oauth token from auth response.",
      });
    }
  });

  test("should throw if `oauth_verifier` is not on the callback URL params", async () => {
    let strategy = new Twitter1Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?oauth_token=TOKEN&oauth_verifierXXX=VERIFIER"
    );
    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should throw Response");
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      expect(error.status).toEqual(400);
      expect(await error.json()).toEqual({
        message: "Missing oauth verifier from auth response.",
      });
    }
  });

  test("should return access token, access token secret, and a minimum user profile", async () => {
    fetchMock.mockResponse(async (req) => {
      const url = new URL(req.url);
      url.search = "";
      switch (url.toString()) {
        case "https://api.twitter.com/oauth/access_token":
          return {
            body: "oauth_token=ACCESS_TOKEN&oauth_token_secret=ACCESS_TOKEN_SECRET&screen_name=na2hiro&user_id=123",
            init: {
              status: 200,
            },
          };
      }
      fail("unknown fetch: " + req.url);
    });

    let strategy = new Twitter1Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?oauth_token=TOKEN&oauth_verifier=VERIFIER"
    );

    verify.mockImplementationOnce(
      ({ accessToken, accessTokenSecret, profile }) => {
        return {
          userId: profile.userId,
          screenName: profile.screenName,
        };
      }
    );

    const user = await strategy.authenticate(request, sessionStorage, OPTIONS);

    expect(user).toEqual({
      userId: "123",
      screenName: "na2hiro",
    });

    expect(fetchMock.mock.calls[0][0]).toMatchInlineSnapshot(
      `"https://api.twitter.com/oauth/access_token"`
    );
    expect(fetchMock.mock.calls[0][1]!.body!.toString()).toMatchInlineSnapshot(
      `"oauth_token=TOKEN&oauth_verifier=VERIFIER&oauth_consumer_key=MY_CLIENT_ID"`
    );

    expect(verify).toHaveBeenLastCalledWith({
      accessToken: "ACCESS_TOKEN",
      accessTokenSecret: "ACCESS_TOKEN_SECRET",
      profile: {
        userId: "123",
        screenName: "na2hiro",
      } as Profile,
    } as Twitter1StrategyVerifyParams);
  });

  test("should fail if verify throws Error", async () => {
    fetchMock.mockResponse(async (req) => {
      const url = new URL(req.url);
      url.search = "";
      switch (url.toString()) {
        case "https://api.twitter.com/oauth/access_token":
          return {
            body: "oauth_token=ACCESS_TOKEN&oauth_token_secret=ACCESS_TOKEN_SECRET",
            init: {
              status: 200,
            },
          };
      }
      fail("unknown fetch: " + req.url);
    });

    let strategy = new Twitter1Strategy<User>(options, verify);
    let request = new Request(
      "https://example.com/callback?oauth_token=TOKEN&oauth_verifier=VERIFIER"
    );

    verify.mockImplementationOnce(() => {
      throw new Error("Nah you're banned, go away.");
    });

    try {
      await strategy.authenticate(request, sessionStorage, OPTIONS);
      fail("Should have thrown");
    } catch (error) {
      if (!(error instanceof Response)) throw error;
      expect(error.status).toEqual(401);
      expect(await error.json()).toEqual({
        message: "Nah you're banned, go away.",
      });
    }
  });
});

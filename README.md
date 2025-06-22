# Remix Auth Twitter ![example branch parameter](https://github.com/na2hiro/remix-auth-twitter/actions/workflows/main.yml/badge.svg?branch=main)

Remix Auth plugin for Twitter [OAuth 2.0](https://developer.x.com/en/docs/authentication/oauth-2-0/user-access-token) and [1.0a](https://developer.x.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens).

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## Example

See [example repo for remix-auth-twitter v3](https://github.com/na2hiro/remix-auth-twitter-example)

## Installation

Install `remix-auth-twitter` npm module along with `remix-auth`:

```shell
npm install remix-auth-twitter remix-auth
```

### Compatibility

| remix-auth-twitter | remix-auth | other notes           |
| ------------------ | ---------- | --------------------- |
| @2                 | @3         | Points to twitter.com |
| @3                 | @3         | Points to x.com       |
| @4                 | @4         | Points to x.com       |

## How to use

### Prerequisites

- Your app is registered to Twitter and you have client ID and secret (OAuth 2.0) or [consumer key and secret (OAuth 1.0a)](https://developer.x.com/en/docs/authentication/oauth-1-0a/api-key-and-secret)
- Your app has [remix-auth](https://github.com/sergiodxa/remix-auth) set up and `authenticator` is provided:
  ```typescript
  // app/services/auth.server.ts
  export let authenticator = ...;
  ```

### Tell the Authenticator to use the Twitter strategy (OAuth 2.0)

Note that profile is not passed to the verify function as it was done for 1.0a. You need to manually hit [/2/users/me](https://developer.x.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me) for example in order to retrieve user's id, screen name, etc. The example uses [`twitter-api-v2`](https://github.com/PLhery/node-twitter-api-v2) to do so.

```typescript jsx
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { Twitter2Strategy } from "remix-auth-twitter";
import TwitterApi from "twitter-api-v2";

export let authenticator = new Authenticator<User>();

const clientID = process.env.TWITTER_CLIENT_ID;
const clientSecret = process.env.TWITTER_CLIENT_SECRET;
if (!clientID || !clientSecret) {
  throw new Error(
    "TWITTER_CLIENT_ID and TWITTER_CLIENT_SECRET must be provided"
  );
}

authenticator.use(
  new Twitter2Strategy(
    {
      clientID,
      clientSecret,
      callbackURL: "https://my-app/login/callback",
      // List of scopes you want to be granted. See
      scopes: ["users.read", "tweet.read", "tweet.write"],
    },
    // Define what to do when the user is authenticated
    async ({ request, tokens }) => {
      /**
       * Get accessToken from OAuth2Tokens object
       * @see https://arcticjs.dev/reference/main/OAuth2Tokens
       */
      const accessToken = tokens.accessToken();

      // In this example I want to use Twitter as identity provider: so resolve identity from the token
      const userClient = new TwitterApi(accessToken);

      const result = await userClient.v2.me({
        "user.fields": ["profile_image_url"],
      });
      // should handle errors
      const { id, username } = result.data;

      // Return a user object.
      // You can also throw Error to reject the login
      return await registerUser(accessToken, id, username);
    }
  )
);
```

### Tell the Authenticator to use the Twitter strategy (OAuth 1.0a)

```typescript jsx
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { Twitter1Strategy } from "remix-auth-twitter";

export let authenticator = new Authenticator<User>();

const consumerKey = process.env.TWITTER_CONSUMER_KEY;
const consumerSecret = process.env.TWITTER_CONSUMER_SECRET;
if (!consumerKey || !consumerSecret) {
  throw new Error(
    "TWITTER_CONSUMER_KEY and TWITTER_CONSUMER_SECRET must be provided"
  );
}

authenticator.use(
  new Twitter1Strategy(
    {
      consumerKey,
      consumerSecret,
      callbackURL: "https://my-app/login/callback",
      alwaysReauthorize: false, // otherwise, ask for permission every time
    },
    // Define what to do when the user is authenticated
    async ({ accessToken, accessTokenSecret, profile }) => {
      // profile contains userId and screenName

      // Return a user object to store in sessionStorage.
      // You can also throw Error to reject the login
      return await registerUser(accessToken, accessTokenSecret, profile);
    }
  ),
  // each strategy has a name and can be changed to use another one
  // same strategy multiple times, especially useful for the OAuth2 strategy.
  "twitter"
);
```

### Set up login/logout flow

Follow the [remix-auth docs](https://github.com/sergiodxa/remix-auth#readme).

The log in flow would look like this:

1. User comes to "login" page (e.g. `/login`).
2. The app will redirect user to Twitter's auth page.
3. Once user finishes auth, Twitter will redirect user back to your app (e.g. `/login/callback`).
4. The app will verify the user and return a user object
5. Save the user object to sessionStorage and redirect user

> **Note:** Storing the user object in session storage and handling redirection after authentication are no longer handled by `remix-auth`. You now need to implement this logic yourself in your authentication flow.

To set up the login flow, follow the code below:

```typescript jsx
// app/routes/login.tsx
import type { Route } from "./+types/_index";
import { authenticator } from "~/services/auth.server";

// Normally this will redirect user to twitter auth page
export const action = async ({ request }: Route.ActionArgs) => {
  const user = await authenticator.authenticate("twitter", request);
};
```

```typescript jsx
// app/routes/login.callback.tsx
import type { Route } from "./+types/_index";
import { redirect } from "react-router";
import { authenticator } from "~/services/auth.server";
import { sessionStorage } from "./session.server";

// This will be called after twitter auth page
export const loader = async ({ request }: Route.LoaderArgs) => {
  const user = await authenticator.authenticate("twitter", request);
  const session = await sessionStorage.getSession(
    request.headers.get("Cookie")
  );

  session.set("user", user);

  return redirect("/app", {
    headers: {
      "Set-Cookie": await sessionStorage.commitSession(session),
    },
  });
};
```

Then let the user do `POST /login`:

```jsx
<Form method="post" action="/login">
  <button>Login</button>
</Form>
```

## Migration from v3 to v4

Here are typical migration steps from v3 to v4.

`remix-auth@4` stopped to handle sessions. They don't handle Remix's sessionStorage anymore.

```diff
// auth.server.ts
-export const authenticator = new Authenticator<UserDocument>(sessionStorage);
+export const authenticator = new Authenticator<UserDocument>();
```

`Strategy` type has been moved from `remix-auth` to `remix-auth/strategy`

```diff
// auth.server.ts
-import { Authenticator, Strategy } from "remix-auth";
+import { Authenticator } from "remix-auth";
+import { Strategy } from "remix-auth/strategy";
```

`Twitter2Strategy`'s second argument, `verify` function, now gets request and tokens

```diff
// auth.server.ts
 authenticator.use(
   new Twitter2Strategy(
     {
       clientID,
       clientSecret,
       callbackURL: `${process.env.HOST}/login/callback`,
       scopes: ["tweet.read", "users.read"],
     },
-    async ({ accessToken, context }) => {
-      return await registerUser(accessToken, context);
+    async ({ request, tokens }) => {
+      const accessToken = tokens.accessToken();
+
+      return await registerUser(accessToken);
     }
   ),
   "twitter"
 );

```

On the login callback route, handle the successful case by persisting the result to session of our choice, and handle thrown error. 

```diff
// login.callback.tsx
 export let loader: LoaderFunction = async ({request}) => {
-  await authenticator.authenticate("twitter", request, {
-    successRedirect: "/dashboard",
-    failureRedirect: "/login/failure"
-  });
+  let user;
+  try {
+    user = authenticator.authenticate("twitter", request),
+  } catch(e) {
+    throw redirect("/login/failure")
+  }
+  const session = await sessionStorage.getSession(
+    request.headers.get("Cookie")
+  );
+
+  session.set("user", user);
+
+  return redirect("/app", {
+    headers: {
+      "Set-Cookie": await sessionStorage.commitSession(session),
+    },
+  });
 };
```

Reading session is all up to us now:

```diff
// auth.server.ts
 export const currentUser = async (request: Request) => {
-  return await authenticator.isAuthenticated(request);
+  const session = await sessionStorage.getSession(request.headers.get("cookie"));
+  return session.get("user");
 };
```

Same for the logic for logout:

```diff
// logout.tsx
 export async function logout(request: Request, returnTo = "/") {
-  await authenticator.logout(request, {
-    redirectTo: returnTo,
-  });
+  let session = await sessionStorage.getSession(request.headers.get("cookie"));
+  session.unset("user");
+
+  return redirect(returnTo, {
+    headers: {
+      "Set-Cookie": await sessionStorage.commitSession(session),
+    },
+  });
 }
```

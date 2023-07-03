# Remix Auth Twitter ![example branch parameter](https://github.com/na2hiro/remix-auth-twitter/actions/workflows/main.yml/badge.svg?branch=main)

Remix Auth plugin for Twitter [OAuth 2.0](https://developer.twitter.com/en/docs/authentication/oauth-2-0/user-access-token) and [1.0a](https://developer.twitter.com/en/docs/authentication/oauth-1-0a/obtaining-user-access-tokens).

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## Demo

Try out ~~[live demo](https://remix-auth-twitter-example.na2hiro.workers.dev/)~~ Currently it doesn't work due to updates on Twitter APIs. You could try cloning the [source code](https://github.com/na2hiro/remix-auth-twitter-example)

## Installation

Install `remix-auth-twitter` npm module along with `remix-auth`:

```shell
npm install remix-auth-twitter remix-auth
```
## How to use

### Prerequisites

* Your app is registered to Twitter and you have client ID and secret (OAuth 2.0) or [consumer key and secret (OAuth 1.0a)](https://developer.twitter.com/en/docs/authentication/oauth-1-0a/api-key-and-secret)
* Your app has [remix-auth](https://github.com/sergiodxa/remix-auth) set up and `authenticator` is provided:
  ```typescript
  // app/services/auth.server.ts
  export let authenticator = ...;
  ```
  
### Tell the Authenticator to use the Twitter strategy (OAuth 2.0)

Note that profile is not passed to the verify function as it was done for 1.0a. You need to manually hit [/2/users/me](https://developer.twitter.com/en/docs/twitter-api/users/lookup/api-reference/get-users-me) for example in order to retrieve user's id, screen name, etc. The example uses [`twitter-api-v2`](https://github.com/PLhery/node-twitter-api-v2) to do so.

```typescript jsx
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { Twitter2Strategy } from 'remix-auth-twitter';
import TwitterApi from 'twitter-api-v2';

export let authenticator = new Authenticator<User>(sessionStorage);

const clientID = process.env.TWITTER_CLIENT_ID;
const clientSecret = process.env.TWITTER_CLIENT_SECRET;
if (!clientID || !clientSecret) {
  throw new Error("TWITTER_CLIENT_ID and TWITTER_CLIENT_SECRET must be provided");
}

authenticator.use(
  new Twitter2Strategy(
    {
      clientID,
      clientSecret,
      callbackURL: "https://my-app/login/callback",
      // List of scopes you want to be granted. See 
      scopes: ["users.read", "tweet.read", "tweet.write"]
    },
    // Define what to do when the user is authenticated
    async ({ accessToken }) => {
      // In this example I want to use Twitter as identity provider: so resolve identity from the token
      const userClient = new TwitterApi(token);

      const result = await userClient.v2.me({
        "user.fields": ["profile_image_url"],
      });
      // should handle errors
      const {id, username} = result.data;

      // Return a user object to store in sessionStorage.
      // You can also throw Error to reject the login
      return await registerUser(
        accessToken,
        id,
        username
      );
    }
  ),
)
```

### Tell the Authenticator to use the Twitter strategy (OAuth 1.0a)

```typescript jsx
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { Twitter1Strategy } from 'remix-auth-twitter';

export let authenticator = new Authenticator<User>(sessionStorage);

const consumerKey = process.env.TWITTER_CONSUMER_KEY;
const consumerSecret = process.env.TWITTER_CONSUMER_SECRET;
if (!consumerKey || !consumerSecret) {
  throw new Error("TWITTER_CONSUMER_KEY and TWITTER_CONSUMER_SECRET must be provided");
}

authenticator.use(
  new Twitter1Strategy(
    {
      consumerKey,
      consumerSecret,
      callbackURL: "https://my-app/login/callback",
      alwaysReauthorize: false // otherwise, ask for permission every time
    },
    // Define what to do when the user is authenticated
    async ({ accessToken, accessTokenSecret, profile }) => {
      // profile contains userId and screenName

      // Return a user object to store in sessionStorage.
      // You can also throw Error to reject the login
      return await registerUser(
        accessToken,
        accessTokenSecret,
        profile
      );
    }
  ),
  // each strategy has a name and can be changed to use another one
  // same strategy multiple times, especially useful for the OAuth2 strategy.
  "twitter"
);
```

### Set up login/logout flow
Follow the [remix-auth docs](https://github.com/sergiodxa/remix-auth#readme) to set up logout flow and `isAuthenticated`.

The log in flow would look like this:

1. User comes to "login" page (e.g. `/login`).
2. The app will redirect user to Twitter's auth page.
3. Once user finishes auth, Twitter will redirect user back to your app (e.g. `/login/callback`).
4. The app will verify the user and let the user login.

To set up the login flow, follow the code below:

```typescript jsx
// app/routes/login.tsx
import {ActionFunction} from "remix";
import {authenticator} from "~/services/auth.server";

// Normally this will redirect user to twitter auth page
export let action: ActionFunction = async ({request}) => {
  await authenticator.authenticate("twitter", request, {
    successRedirect: "/dashboard", // Destination in case the user is already logged in
  });
};
```

```typescript jsx
// app/routes/login.callback.tsx
import {LoaderFunction} from "remix";
import {authenticator} from "~/services/auth.server";

// This will be called after twitter auth page 
export let loader: LoaderFunction = async ({request}) => {
  await authenticator.authenticate("twitter", request, {
    successRedirect: "/dashboard",
    failureRedirect: "/login/failure"
  });
};
```

Then let the user do `POST /login`:
```jsx
<Form method="post" action="/login">
  <button>Login</button>
</Form>
```

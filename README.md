# Remix Auth Twitter

Remix Auth plugin for Twitter OAuth 1.0a.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## Demo

Try out [live demo](https://github.com/na2hiro/remix-auth-twitter) ([source code](https://github.com/na2hiro/remix-auth-twitter))

## Installation

Install `remix-auth-twitter` npm module along with `remix-auth`:

```shell
npm install remix-auth-twitter remix-auth
```
## How to use

### Prerequisites

* Your app is registered to Twitter and has consumer key and secret issued https://developer.twitter.com/en/docs/authentication/oauth-1-0a/api-key-and-secret
* Your app has [remix-auth](https://github.com/sergiodxa/remix-auth) set up and `authenticator` is provided:
  ```typescript
  // app/services/auth.server.ts
  export let authenticator = ...;
  ```

### Tell the Authenticator to use the Twitter strategy

```typescript jsx
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { TwitterStrategy } from 'remix-auth-twitter';

export let authenticator = new Authenticator<User>(sessionStorage);

const clientID = process.env.TWITTER_CONSUMER_KEY;
const clientSecret = process.env.TWITTER_CONSUMER_SECRET;
if (!clientID || !clientSecret) {
  throw new Error("TWITTER_CONSUMER_KEY and TWITTER_CONSUMER_SECRET must be provided");
}

authenticator.use(
  new TwitterStrategy(
    {
      clientID,
      clientSecret,
      callbackURL: "https://my-app/login/callback",
    },
    // Define what to do when the user is authenticated
    async ({ accessToken, accessTokenSecret, profile }) => {
      // profile contains all the info from `account/verify_credentials`
      // https://developer.twitter.com/en/docs/twitter-api/v1/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials

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
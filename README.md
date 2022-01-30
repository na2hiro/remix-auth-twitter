# Remix Auth Twitter

Remix Auth plugin for Twitter OAuth 1.0a.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

<!-- If it doesn't support one runtime, explain here why -->

## Installation

Install `remix-auth-twitter` npm module along with `remix-auth`:

```shell
npm install remix-auth-twitter remix-auth
```
## How to use

### Prerequisites

* Your app is registered to Twitter and you have consumer key and secret issued https://developer.twitter.com/en/docs/authentication/oauth-1-0a/api-key-and-secret

### Set up Remix Auth

Follow the guide of [remix-auth](https://github.com/sergiodxa/remix-auth) for setting up `authenticator`. Let's say we set up like following:

```typescript
// app/services/session.server.ts
import { createCookieSessionStorage } from "remix";

// export the whole sessionStorage object
export let sessionStorage = ...;
```

```typescript
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";

export let authenticator = new Authenticator<User>(sessionStorage);
```

### Use Remix Auth Twitter

Configure `TwitterStrategy` and pass it to `authenticator.use()`:

```typescript jsx
// app/services/auth.server.ts
import { Authenticator } from "remix-auth";
import { sessionStorage } from "~/services/session.server";
import { TwitterStrategy } from 'remix-auth-twitter';

export let authenticator = new Authenticator<User>(sessionStorage);

const clientID = process.env.TWITTER_CONSUMER_KEY;
const clientSecret = process.env.TWITTER_CONSUMER_SECRET;
if (!clientID || !clientSecret) {
  throw new Error("TWITTER_CONSUMER_KEY nor TWITTER_CONSUMER_SECRET not given");
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
  "twitter"
);
```

### Set up login flow
From now on, this is pretty much `remix-auth` thing and you can rely on the docs there. Keep reading if you want to know the exact steps to get there.

We need 2 end points: `login`, `login/callback`.

```typescript jsx
// app/routes/login.tsx
import {ActionFunction} from "remix";
import {authenticator} from "~/services/auth.server";

export let action: ActionFunction = async ({request}) => {
  // Normally this will redirect user to twitter auth page
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

Finally, let the user do `POST /login` to trigger log in.
```typescript jsx
<Form method="post" action="/login">
  <button>Login</button>
</Form>
```
### Set up logout flow
```typescript jsx
// app/routes/logout.tsx
import {ActionFunction} from "remix";
import {authenticator} from "~/services/auth.server";

export let action: ActionFunction = async ({request}) => {
  await authenticator.logout(request, {
    redirectTo: "/"
  });
}
```

Then, of course, trigger `POST /logout`.

```typescript jsx
<Form method="post" action="/logout">
  <button>Logout</button>
</Form>
```
### Retrieve user session

```typescript jsx
// Returns the user object which is returned by your `verify` function.
// `null` if not logged in.
const currentUser = await authenticator.isAuthenticated(request);
```

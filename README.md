# Remix Auth Twitter

Remix Auth plugin for Twitter OAuth 1.0a.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

<!-- If it doesn't support one runtime, explain here why -->

## How to use

Example of `auth.server.ts`:

```typescript jsx
export const authenticator = new Authenticator<UserDocument>(sessionStorage);

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
        // This is called when the user is authenticated    
        async ({accessToken, accessTokenSecret, profile}) => {
            // profile contains all the info from `account/verify_credentials`
            // https://developer.twitter.com/en/docs/twitter-api/v1/accounts-and-users/manage-account-settings/api-reference/get-account-verify_credentials

            return await registerUser(
                accessToken,
                accessTokenSecret,
                profile
            );
        }
    ),
    // this is optional, but if you setup more than one OAuth2 instance you will
    // need to set a custom name to each one
    "twitter"
);
```

For the usage of `authenticator`, see [sargiodxa/remix-auth](https://github.com/sergiodxa/remix-auth).
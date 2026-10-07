# Contribution

## Setup

Run `bun install` to install the dependencies.

Run the tests with `bun test`.

Run the biome check with `bun run quality`.

Run the biome formatter with `bun run quality:fix`.

Run the typechecker with `bun run typecheck`.

## Publishing

The Publish workflow uses npm trusted publishing. Configure the
`remix-auth-twitter` package on npmjs.com with a GitHub Actions trusted
publisher for owner `na2hiro`, repository `remix-auth-twitter`, and workflow
filename `publish.yml`. Allow direct `npm publish` for that publisher.

Publishing a GitHub release runs the workflow. To retry a release after a
workflow failure, manually run the Publish workflow with its existing tag
(for example, `v4.1.0`). The workflow checks out that tag and verifies that it
matches the package version before publishing.

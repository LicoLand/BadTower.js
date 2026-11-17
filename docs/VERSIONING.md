# Version source

The root `package.json` `version` is the only release version a human
chooses. Everything else is derived or checked:

- `packages/station-core/package.json`
- `packages/plugin-licoarc-mailbox/package.json`
- `apps/station/package.json`
- `package-lock.json` (root and each workspace entry)
- the newest `## [<version>]` heading in `CHANGELOG.md`

`npm run check:version` fails if any of those disagree. It runs first in
`npm run check` and in the CI `source` job, so a bump cannot land
half-applied.

## Bumping

1. Change the root `package.json` version.
2. Change every workspace manifest to the same version.
3. Refresh the lockfile with `npm install --package-lock-only`.
4. Add a `CHANGELOG.md` entry with exactly that version in the heading.
5. Run `npm run check:version` (and then `npm run check`).

The current source version is `0.0.0-preview.0`. It is a preview
baseline, not a claim that a tag, image, or hosted deployment exists.

## Native contract version is separate

The native contract has its own `major.minor` identifier (`1.0`) and its
own change rules in `NATIVE-CONTRACT.md`. A package release may ship the
same contract version; a contract change must update the contract
constant, docs, test and changelog in the same commit. Do not use the
package version to decide native wire compatibility.

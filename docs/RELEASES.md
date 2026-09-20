# Releases and updates

A release is a tag `vMAJOR.MINOR.PATCH`, made with one command on the
maintainer's Mac:

```bash
make release                  # the next patch version after the highest tag (the first: v0.1.0)
make release BUMP=minor       # or major
make release VERSION=v1.4.0   # a version of your choice; the same line resumes a release that stopped halfway
make release-next             # only says which version it would be
```

Two halves, and the signing keys are all in one of them:

| | where | what |
|---|---|---|
| 1 | here | checks (clean tree, HEAD is `origin/main`, the release key is one the builds know, the version is newer than every tag), tags, pushes the tag |
| 2 | CI, `.gitea/workflows/release.yml` | tests, Linux binaries, the image; parks them in a **draft** release with `build.json`, a record of what it built. CI signs nothing and holds no signing key |
| 3 | here, while CI works | the Mac app: universal, signed with your Developer ID, notarized, stapled (`apps/macos/build-app.sh`, `notarize.sh`; the credentials stay in your keychain) |
| 4 | here | downloads CI's files, compares them with `build.json` and the tagged commit, writes the manifest over everything, **signs it with the release key**, checks the signature the way clients will |
| 5 | here | uploads Mac app, manifest and signature, publishes the draft, confirms that `releases/latest` answers the new version |

Nothing is visible to clients before step 5: they read `releases/latest`, and a
draft is not that. The result is a Gitea release with

| asset | for |
|---|---|
| `boundgate-<v>-linux-{amd64,arm64}.tar.gz` | control plane, node, CLI, mux as plain binaries |
| `BoundGate-<version>.dmg` | the macOS app for people: Developer ID signed, notarized, stapled |
| `BoundGate-<version>-macos.zip` | the same app, what the built-in updater downloads |
| `manifest.json`, `manifest.json.sig` | the signed description of all of the above |

and the container image `gitlab.net407.com/sbh/boundgate:<v>`, which the
manifest names **by digest**.

## The manifest is the trust anchor, not the server

```json
{"type":"boundgate-release","version":"v1.2.3","commit":"…","created":"…",
 "image":{"ref":"gitlab.net407.com/sbh/boundgate","digest":"sha256:…"},
 "assets":[{"name":"…","kind":"app|binaries|dmg","os":"…","arch":"…","size":1,"sha256":"…"}]}
```

`manifest.json.sig` is an OpenSSH signature (SSHSIG, namespace
`boundgate-release`) by a release key. The public keys are compiled into every
build (`internal/update/release_keys`) and lie next to `update.sh`
(`deploy/prod/release_keys`). A client

* installs nothing the signed manifest does not name, by SHA-256 (the image:
  by digest, not by a tag somebody could move);
* refuses a manifest whose version differs from the release tag it was offered
  under (an old signed manifest under a new tag), and anything that is not
  newer than what runs (no downgrade);
* sends its access token, if it has one, only to the configured Gitea, never
  to where an asset link points.

So Gitea, its database and whoever can edit a release are trusted with being
reachable and nothing else. By hand:

```bash
sed 's/^/boundgate-release /' release_keys | grep -v '#' > allowed
ssh-keygen -Y verify -f allowed -I boundgate-release -n boundgate-release -s manifest.json.sig < manifest.json
sha256sum -c <(jq -r '.assets[] | "\(.sha256)  \(.name)"' manifest.json)
```

## Setting it up (once)

1. **Release key**: `make release-key`. It asks for a passphrase, creates
   `private/release_signing_key` (git-ignored) and appends the public half to
   both `release_keys` files; commit those. The private half never leaves this
   machine except into your offline backup. A FIDO2 key works as well
   (`ssh-keygen -t ed25519-sk`, its `.pub` line into both files, then
   `RELEASE_KEY=~/.ssh/that_key make release`; signing asks for a touch, and
   needs Homebrew's OpenSSH, which the script prefers). Builds made before the
   commit with the key have none and refuse all updates. List a second key as
   a reserve from the start (R91).
2. **Access token** for the release API: Gitea > Settings > Applications, scope
   `write:repository`, one line in `private/gitea_token` (`chmod 600`), or
   `GITEA_TOKEN` in the environment. The script hands it to curl in a file, not
   on a command line, and sends it to the configured Gitea only.
3. **Mac app**: a *Developer ID Application* certificate in your keychain and
   notarytool credentials stored once, best an App Store Connect team API key
   (`xcrun notarytool store-credentials boundgate-notary …`, see
   `apps/macos/notarize.sh`). An "Apple Development" certificate is not enough:
   other people's Macs only run Developer ID signed, notarized apps.
   `NO_MAC=1 make release` makes a release without the app.
4. **CI**: `REGISTRY_TOKEN` as for the image workflow; `RELEASE_TOKEN`
   (write:repository) only if the job's own token may not create releases.
5. **Anonymous downloads**: this Gitea answers visitors with "Only signed in
   user is allowed to call APIs" (`REQUIRE_SIGNIN_VIEW`). For third parties the
   repository must be public and that setting off (or releases mirrored to a
   public place, `update.url`). Until then every updater needs a read token:
   `update.token_file` in `node.yaml`, `BOUNDGATE_UPDATE_TOKEN_FILE` for
   `update.sh`.

Before it tags anything, the script checks what would stop it later: that the
token gets write access to the repository, that the keychain has a Developer ID
identity, and that notarytool can use its profile. What it cannot see in
advance is the token's scope: a read-only token fails at the first upload.

If something fails on the way (CI red, notarization slow, no network), fix it
and run `make release VERSION=<that version>` again: the tag exists, a finished
Mac build is kept, files of the earlier attempt are replaced. A re-run of the
CI job replaces its own draft and never touches a published release. Tested
against a stand-in for Gitea by `make release-test`.

## Updating

**The Mac app.** The daemon of a release build asks the release API every six
hours (`update: {check, url, repo, token_file, interval}` in `node.yaml`) and
verifies what it finds; the app shows "Update available" and, from the menu,
"Check for Updates…". "Install and restart" disconnects, and the root daemon
downloads the zip, checks it against the manifest, unpacks it next to the app,
and requires: same bundle identifier, a valid code signature **of the same
team as the running app**, Gatekeeper's acceptance (notarization). Only then
it swaps the bundles (rename, undone if it fails). The daemon notices that its
executable was replaced and restarts from the new one; the app opens again.
No administrator password: the daemon already is root, and the only thing it
can be talked into installing is a newer release signed by the release key
and by the same Apple developer. `boundgatectl update [-install]` does the
same from a terminal. A development build ("dev") looks but never installs.

**Unattended hosts**: `deploy/prod/update.sh`, for cron:

```
17 3 * * *  cd /opt/boundgate && ./update.sh -q
```

With the kits of `deploy/prod` it pulls the image by the signed digest, writes
`BOUNDGATE_IMAGE=…@sha256:…` and `BOUNDGATE_RELEASE` to `.env`,
`docker compose up -d`, and returns to the previous image if the containers do
not stay up. `MODE=binaries` replaces installed binaries from the tarball
(checked against the manifest) and runs `RESTART_CMD`. `update.sh check` only
reports. `-q` is silent unless something was updated or failed, so cron mails
exactly those. Tested by `make update-test`.

## What remains (SECURITY.md R88–R91)

The release key and the Developer ID identity exist on the maintainer's Mac
only; Gitea, its admins and its runners cannot sign a release. What the
maintainer signs, though, is what CI built: the Linux binaries and the image
come from the runner, and step 4 can only check that they are the files CI
recorded for the tagged commit, not that the runner built them honestly. A
compromised runner therefore still reaches Linux nodes through a release the
maintainer signs in good faith. Closing that needs a reproducible build that
the maintainer repeats locally and compares (the Go binaries are built with
`-trimpath` and no cgo, which is most of the way); not done yet.

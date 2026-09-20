# Releases and updates

A release is a tag `vMAJOR.MINOR.PATCH`. `.gitea/workflows/release.yml` turns
it into a Gitea release with

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

## Setting the pipeline up (once)

1. **Release key**: `make release-key` on your machine. It creates
   `private/release_signing_key` (git-ignored) and appends the public half to
   both `release_keys` files; commit those. Put the private half into the
   repository secret `RELEASE_SIGNING_KEY`. Builds made before that commit
   have no key and refuse all updates.
2. `REGISTRY_TOKEN` as for the image workflow; `RELEASE_TOKEN` (write:repository)
   only if the job's own token may not create releases.
3. **macOS app**: Swift, codesign and notarytool exist only on macOS, so this
   part needs an act_runner on a Mac with Xcode. Name its label in the
   repository *variable* `MACOS_RUNNER`. Secrets: `MACOS_CERT_P12` (base64 of a
   .p12 with a *Developer ID Application* certificate and its key),
   `MACOS_CERT_PASSWORD`, and an App Store Connect API key for notarization:
   `NOTARY_KEY_P8`, `NOTARY_KEY_ID`, `NOTARY_ISSUER`. The job imports the
   certificate into a keychain of its own and deletes it afterwards; the Mac
   needs no Go (the darwin binaries come from the Linux job). Without
   `MACOS_RUNNER` a release is published without the Mac app and says so.
   An "Apple Development" certificate is not enough: other people's Macs only
   run Developer ID signed, notarized apps.
4. **Anonymous downloads**: this Gitea answers visitors with "Only signed in
   user is allowed to call APIs" (`REQUIRE_SIGNIN_VIEW`). For third parties the
   repository must be public and that setting off (or releases mirrored to a
   public place, `update.url`). Until then every updater needs a read token:
   `update.token_file` in `node.yaml`, `BOUNDGATE_UPDATE_TOKEN_FILE` for
   `update.sh`.

Then: `git tag v0.9.0 && git push origin v0.9.0`. The release appears (as a
draft until every asset is uploaded, so that `releases/latest` never points at
half a release).

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

The release key and the Developer ID certificate are CI secrets: the Gitea
instance and its runners can sign a release. Keeping the release key off the
server is possible with the same files: sign `manifest.json` by hand
(`ssh-keygen -Y sign -n boundgate-release`, a YubiKey-held `sk-` key works)
and upload the `.sig` yourself; list only that key in `release_keys`.

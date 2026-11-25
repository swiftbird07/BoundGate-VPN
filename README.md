# BoundGate

BoundGate is a device-bound zero-trust overlay network: every device is a node
with a key that never leaves its hardware, an administrator signs what each
node may do, and a policy decides every flow.

This repository holds the releases and what the installers fetch. The source
code is not public.

## Install

A server with Docker (control plane and hub, another node, or the reverse
proxy). The script asks a few questions:

```sh
curl -fsSL https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/prod/setup.sh | sh
```

Windows, in PowerShell as administrator:

```powershell
irm https://raw.githubusercontent.com/swiftbird07/BoundGate-VPN/main/deploy/windows/setup.ps1 | iex
```

The macOS app (`.dmg`) and the Android app (`.apk`) are in the
[releases](https://github.com/swiftbird07/BoundGate-VPN/releases).

## Verify

Every release has a `manifest.json`, signed with a release key
(`deploy/prod/release_keys`), that names every file of the release and the
container image by its digest. The installers and the updaters check it before
they install anything. By hand:

```sh
sed 's/^/boundgate-release /' deploy/prod/release_keys > allowed
ssh-keygen -Y verify -f allowed -I boundgate-release -n boundgate-release -s manifest.json.sig < manifest.json
```

## License

Proprietary. See [LICENSE](LICENSE).

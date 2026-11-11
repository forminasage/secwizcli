# NMC Security Wizard CLI

Command line tool for creating SSL certificates, SSH host keys, CA root certificates and CSRs for Schneider Electric / APC Network Management Cards. It wraps cryptlib (`cl32.dll`).

This source was recovered by decompiling Schneider Electric's NMCSecurityWizardCLI v1.0.0 (`NMCSecurityWizardCLI.exe`, SHA-256 `8a49ce983ad4233888312c8dabf766b3baf8fa8cbe22b6378aa2a0dc7c384934`). The original is copyright Schneider Electric.

## Changes from v1.0.0

- `-d` (DNS Name SAN) can be repeated to put multiple DNS names in one certificate or CSR. Previously only the last `-d` was kept.
- The certificate summary lists every DNS name.
- cryptlib upgraded from the bundled 2016 build to 3.4.9.6. The old build only allows one value per SAN field, which is why a second `-d` failed with error -12 in v1.0.5.
- `.p15` key files are written in the layout the NMC firmware accepts, the one [apc-p15-tool](https://github.com/gregtwallace/apc-p15-tool) produces. Stock 3.4.9.6 writes a newer PKCS#15 layout that cards reject without an error. `cryptlib/nmc-p15.patch` restores non-extended private key records, 5000 key wrap iterations, and SHA-1 content key derivation.

The key file password is fixed by the firmware (`user`), so treat `.p15` files as unencrypted private keys.

Email, URI and IP SANs are still limited to one each. cryptlib 3.4.9.6 rejects DNS names shorter than 7 characters, so a short name like `ups01` must be given as an FQDN instead.

```
NMCSecurityWizardCLI --csr -o ups01 -n ups01.corp.com -c US -d ups01.corp.com -d ups01 -d ups01.mgmt.corp.com
```

## Requirements

- Windows with .NET Framework 2.0/3.5 (on Windows 10 and 11, enable ".NET Framework 3.5" in Windows Features).
- The x86 Microsoft Visual C++ 2015+ Redistributable, which the cryptlib 3.4.9.6 DLL needs (`VCRUNTIME140.dll`).
- `cl32.dll` in the current directory.

## Building

Requires the .NET SDK (any recent version; it targets .NET Framework 2.0, x86).

```
dotnet build -c Release
```

`cl32.dll` is built from the [cryptlib repository](https://github.com/cryptlib/cryptlib) at tag `v3.4.9.6` with `cryptlib/nmc-p15.patch` applied. `.github/workflows/windows.yml` builds it, runs the exe against it on Windows, and uploads the release files. cryptlib's license is in `cryptlib/COPYING`.

The C# binding in `cryptlib/` is the one from the original tool, not upstream's `bindings/cryptlib.cs`. Every constant the tool uses matches the 3.4.9.6 native header, while upstream's generated binding has several certificate extension IDs off by two.

## Testing

`test/e2e.sh` runs every command against a native cryptlib build and checks the output with OpenSSL. `test/p15check` decodes each key file the way apc-p15-tool encodes one and fails on any difference. Build cryptlib from its source with the patch applied (`git apply`, then `make shared`), then:

```
test/e2e.sh /path/to/cryptlib/libcl.3.4.dylib
```

# NMC Security Wizard CLI

Command line tool for creating SSL certificates, SSH host keys, CA root certificates and CSRs for Schneider Electric / APC Network Management Cards. It wraps cryptlib (`cl32.dll`).

This source was recovered by decompiling Schneider Electric's NMCSecurityWizardCLI v1.0.0 (`NMCSecurityWizardCLI.exe`, SHA-256 `8a49ce983ad4233888312c8dabf766b3baf8fa8cbe22b6378aa2a0dc7c384934`). The original is copyright Schneider Electric.

## Changes from v1.0.0

- `-d` (DNS Name SAN) can be repeated to put multiple DNS names in one certificate or CSR. Previously only the last `-d` was kept.
- The certificate summary lists every DNS name.
- cryptlib upgraded from the bundled 2016 build to 3.4.9.6. The old build only allows one value per SAN field, which is why a second `-d` failed with error -12 in v1.0.5.

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

`cl32.dll` is the 32-bit prebuilt DLL from the [cryptlib repository](https://github.com/cryptlib/cryptlib) at tag `v3.4.9.6`, which is also where its complete source is. cryptlib's license is in `cryptlib/COPYING`.

The C# binding in `cryptlib/` is the one from the original tool, not upstream's `bindings/cryptlib.cs`. Every constant the tool uses matches the 3.4.9.6 native header, while upstream's generated binding has several certificate extension IDs off by two.

## Testing

`test/e2e.sh` runs every command against a native cryptlib build and checks the output with OpenSSL. Build cryptlib from its source with `make shared`, then:

```
test/e2e.sh /path/to/cryptlib/libcl.3.4.dylib
```

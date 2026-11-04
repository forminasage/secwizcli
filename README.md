# NMC Security Wizard CLI

Command line tool for creating SSL certificates, SSH host keys, CA root certificates and CSRs for Schneider Electric / APC Network Management Cards. It wraps cryptlib (`cl32.dll`).

This source was recovered by decompiling Schneider Electric's NMCSecurityWizardCLI v1.0.0 (`NMCSecurityWizardCLI.exe`, SHA-256 `8a49ce983ad4233888312c8dabf766b3baf8fa8cbe22b6378aa2a0dc7c384934`). The original is copyright Schneider Electric.

## Changes from v1.0.0

- `-d` (DNS Name SAN) can be repeated to put multiple DNS names in one certificate or CSR. Previously only the last `-d` was kept.
- The certificate summary lists every DNS name.

Email, URI and IP SANs are still limited to one each.

```
NMCSecurityWizardCLI --csr -o ups01 -n ups01.corp.com -c US -d ups01.corp.com -d ups01 -d ups01.mgmt.corp.com
```

## Building

Requires the .NET SDK (any recent version; it targets .NET Framework 2.0, x86).

```
dotnet build -c Release
```

The output exe needs `cl32.dll` (cryptlib 3.4.4, 32-bit) in the current directory when run. Get it from the release zip or the original Schneider Electric download.

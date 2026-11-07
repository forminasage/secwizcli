#!/bin/bash
# End-to-end check of every command against a native cryptlib build.
# Usage: test/e2e.sh /path/to/libcl.dylib   (or libcl.so)
set -euo pipefail

lib=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

dotnet build "$here/Harness.csproj" -c Release -o "$work/bin" >/dev/null
cp "$lib" "$work/bin/cl32.dll"
cp "$lib" "$work/cl32.dll"
cd "$work"

tool() { dotnet "$work/bin/Harness.dll" "$@"; }
fail() { echo "FAIL: $*"; exit 1; }
sans() { openssl "$1" -in "$2" -noout -text | grep -A1 'Subject Alternative Name' | tail -1 | tr -d ' '; }
want='email:admin@corp.com,DNS:ups01.corp.com,DNS:ups01.lan,DNS:ups01.mgmt.corp.com,URI:https://ups01.corp.com,IPAddress:10.1.2.3'
san_args=(-e admin@corp.com -d ups01.corp.com -d ups01.lan -d ups01.mgmt.corp.com -i https://ups01.corp.com -a 10.1.2.3)

tool --csr -o req -n ups01.corp.com -c US "${san_args[@]}" >/dev/null
openssl req -in req.csr -noout -verify 2>/dev/null || fail "CSR signature"
[ "$(sans req req.csr)" = "$want" ] || fail "CSR SANs: $(sans req req.csr)"

tool --caroot -o ca -n ca.corp.com -c US -f 01/01/2026 -t 01/01/2036 >/dev/null
openssl x509 -in ca.crt -noout -ext basicConstraints | grep -q 'CA:TRUE' || fail "CA basicConstraints"

out=$(tool --sslcert -o srv -r ca -n ups01.corp.com -c US -f 01/01/2026 -t 01/01/2028 "${san_args[@]}")
openssl verify -CAfile ca.crt srv.crt >/dev/null || fail "server cert does not chain to CA"
[ "$(sans x509 srv.crt)" = "$want" ] || fail "server cert SANs: $(sans x509 srv.crt)"
[ "$(grep -c 'DNS Name:' <<<"$out")" = 3 ] || fail "summary should list 3 DNS names"
openssl x509 -in srv.crt -noout -dates | grep -q 'notAfter=Jan  1 00:00:00 2028 GMT' || fail "server cert validity: $(openssl x509 -in srv.crt -noout -dates)"
grep -q 'Valid To: 01/01/2028' <<<"$out" || fail "summary validity date"

# CA-signed import: sign the CSR with an OpenSSL CA, then import with the CSR's key
openssl req -x509 -newkey rsa:2048 -nodes -keyout oca.key -out oca.crt -subj /CN=oca -days 1 2>/dev/null
openssl x509 -req -in req.csr -CA oca.crt -CAkey oca.key -copy_extensions copy -days 1 -out signed.crt 2>/dev/null
out=$(tool --import -o imp -s signed.crt -p req)
[ "$(grep -c 'DNS Name:' <<<"$out")" = 3 ] || fail "import summary should list 3 DNS names"

tool --sshkey -o ssh >/dev/null
[ -s ssh.p15 ] || fail "SSH key not written"

out=$(tool --csr -o short -n ups01.corp.com -c US -d ups01 || true)
grep -q 'DNS name (7 characters minimum)' <<<"$out" || fail "short DNS name not rejected cleanly"

echo "PASS"

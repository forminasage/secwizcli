// Decodes an NMC .p15 private key the way apc-p15-tool encodes one and fails
// on any deviation from that format, which the cards are known to accept.
// Usage: dotnet run p15check.cs -- file.p15
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;

static void Check(bool ok, string what) { if (!ok) throw new Exception(what); }

var file = File.ReadAllBytes(args[0]);
var root = new AsnReader(file.AsMemory(228), AsnEncodingRules.DER).ReadSequence();
root.ReadObjectIdentifier();
var objs = root.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
objs.ReadInteger();
var privKeys = objs.ReadSequence().ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0))
	.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
Check(privKeys.PeekTag() == Asn1Tag.Sequence, "private key object is not privateRSAKey (extended format?)");
var keyObj = privKeys.ReadSequence();
keyObj.ReadSequence();
keyObj.ReadSequence();
if (keyObj.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, true)) keyObj.ReadSequence(keyObj.PeekTag());
var env = keyObj.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1)).ReadSequence()
	.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4));

Check(env.ReadInteger() == 2, "AuthEnvelopedData version");
var pwri = env.ReadSetOf().ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
pwri.ReadInteger();
var kdf = pwri.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
Check(kdf.ReadObjectIdentifier() == "1.2.840.113549.1.5.12", "KEK KDF is not PBKDF2");
var kdfParams = kdf.ReadSequence();
var kekSalt = kdfParams.ReadOctetString();
Check(kdfParams.ReadInteger() == 5000, "KEK iterations are not 5000");
Check(kdfParams.ReadSequence().ReadObjectIdentifier() == "1.2.840.113549.2.9", "KEK PRF is not HMAC-SHA256");
var kekAlg = pwri.ReadSequence();
Check(kekAlg.ReadObjectIdentifier() == "1.2.840.113549.1.9.16.3.9", "key wrap is not PWRI-KEK");
var kekCipher = kekAlg.ReadSequence();
Check(kekCipher.ReadObjectIdentifier() == "1.2.840.113549.3.7", "key wrap cipher is not 3DES");
var kekIv = kekCipher.ReadOctetString();
var wrapped = pwri.ReadOctetString();

var eci = env.ReadSequence();
eci.ReadObjectIdentifier();
var encAlgDer = eci.PeekEncodedValue().ToArray();
var encAlg = eci.ReadSequence();
Check(encAlg.ReadObjectIdentifier() == "1.2.840.113549.1.9.16.3.15", "content cipher is not authEnc128");
var authEnc = encAlg.ReadSequence();
Check(authEnc.PeekTag() == Asn1Tag.Sequence, "authEnc carries an explicit PRF (default SHA-1 expected)");
var contentCipher = authEnc.ReadSequence();
Check(contentCipher.ReadObjectIdentifier() == "1.2.840.113549.3.7", "content cipher is not 3DES");
var contentIv = contentCipher.ReadOctetString();
Check(authEnc.ReadSequence().ReadObjectIdentifier() == "1.2.840.113549.2.9", "MAC is not HMAC-SHA256");
var cipherText = eci.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
var mac = env.ReadOctetString();

// RFC 3211 unwrap: strip the outer CBC layer, whose IV is the decrypted last block, then the inner one.
var kek = Rfc2898DeriveBytes.Pbkdf2("user"u8, kekSalt, 5000, HashAlgorithmName.SHA256, 24);
using var des = TripleDES.Create();
des.Key = kek;
int n = wrapped.Length;
var lastIv = des.DecryptCbc(wrapped.AsSpan(n - 8), wrapped.AsSpan(n - 16, 8), PaddingMode.None);
var inner = des.DecryptCbc(wrapped, lastIv, PaddingMode.None);
inner = des.DecryptCbc(inner, kekIv, PaddingMode.None);
var cek = inner.AsSpan(4, inner[0]).ToArray();
Check(inner[1] == (byte)~cek[0] && inner[2] == (byte)~cek[1] && inner[3] == (byte)~cek[2], "CEK check bytes");

var macKey = Rfc2898DeriveBytes.Pbkdf2(cek, "authentication"u8.ToArray(), 1, HashAlgorithmName.SHA1, 32);
Check(HMACSHA256.HashData(macKey, encAlgDer.Concat(cipherText).ToArray()).SequenceEqual(mac), "MAC mismatch");
des.Key = Rfc2898DeriveBytes.Pbkdf2(cek, "encryption"u8.ToArray(), 1, HashAlgorithmName.SHA1, 24);
var plain = des.DecryptCbc(cipherText, contentIv, PaddingMode.PKCS7);

var key = new AsnReader(plain, AsnEncodingRules.DER).ReadSequence();
BigInteger Field(int tag) => key.ReadInteger(new Asn1Tag(TagClass.ContextSpecific, tag));
var (p, q) = (Field(3), Field(4));
Field(5); Field(6);
Check(Field(7) * q % p == 1, "decrypted RSA key is inconsistent (qInv)");
Console.WriteLine($"OK {args[0]}: {BigInteger.Multiply(p, q).GetBitLength()}-bit RSA, apc-p15-tool format");

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace cryptlib;

public class crypt
{
	public const int ALGO_NONE = 0;

	public const int ALGO_DES = 1;

	public const int ALGO_3DES = 2;

	public const int ALGO_IDEA = 3;

	public const int ALGO_CAST = 4;

	public const int ALGO_RC2 = 5;

	public const int ALGO_RC4 = 6;

	public const int ALGO_RESERVED1 = 7;

	public const int ALGO_AES = 8;

	public const int ALGO_RESERVED2 = 9;

	public const int ALGO_DH = 100;

	public const int ALGO_RSA = 101;

	public const int ALGO_DSA = 102;

	public const int ALGO_ELGAMAL = 103;

	public const int ALGO_RESERVED3 = 104;

	public const int ALGO_ECDSA = 105;

	public const int ALGO_ECDH = 106;

	public const int ALGO_RESERVED4 = 200;

	public const int ALGO_RESERVED5 = 201;

	public const int ALGO_MD5 = 202;

	public const int ALGO_SHA1 = 203;

	public const int ALGO_RESERVED6 = 204;

	public const int ALGO_SHA2 = 205;

	public const int ALGO_SHA256 = 205;

	public const int ALGO_SHAng = 206;

	public const int ALGO_RESREVED_7 = 300;

	public const int ALGO_HMAC_SHA1 = 301;

	public const int ALGO_RESERVED8 = 302;

	public const int ALGO_HMAC_SHA2 = 303;

	public const int ALGO_HMAC_SHAng = 304;

	public const int ALGO_LAST = 305;

	public const int ALGO_FIRST_CONVENTIONAL = 1;

	public const int ALGO_LAST_CONVENTIONAL = 99;

	public const int ALGO_FIRST_PKC = 100;

	public const int ALGO_LAST_PKC = 199;

	public const int ALGO_FIRST_HASH = 200;

	public const int ALGO_LAST_HASH = 299;

	public const int ALGO_FIRST_MAC = 300;

	public const int ALGO_LAST_MAC = 399;

	public const int MODE_NONE = 0;

	public const int MODE_ECB = 1;

	public const int MODE_CBC = 2;

	public const int MODE_CFB = 3;

	public const int MODE_GCM = 4;

	public const int MODE_LAST = 5;

	public const int KEYSET_NONE = 0;

	public const int KEYSET_FILE = 1;

	public const int KEYSET_HTTP = 2;

	public const int KEYSET_LDAP = 3;

	public const int KEYSET_ODBC = 4;

	public const int KEYSET_DATABASE = 5;

	public const int KEYSET_ODBC_STORE = 6;

	public const int KEYSET_DATABASE_STORE = 7;

	public const int KEYSET_LAST = 8;

	public const int DEVICE_NONE = 0;

	public const int DEVICE_FORTEZZA = 1;

	public const int DEVICE_PKCS11 = 2;

	public const int DEVICE_CRYPTOAPI = 3;

	public const int DEVICE_HARDWARE = 4;

	public const int DEVICE_LAST = 5;

	public const int CERTTYPE_NONE = 0;

	public const int CERTTYPE_CERTIFICATE = 1;

	public const int CERTTYPE_ATTRIBUTE_CERT = 2;

	public const int CERTTYPE_CERTCHAIN = 3;

	public const int CERTTYPE_CERTREQUEST = 4;

	public const int CERTTYPE_REQUEST_CERT = 5;

	public const int CERTTYPE_REQUEST_REVOCATION = 6;

	public const int CERTTYPE_CRL = 7;

	public const int CERTTYPE_CMS_ATTRIBUTES = 8;

	public const int CERTTYPE_RTCS_REQUEST = 9;

	public const int CERTTYPE_RTCS_RESPONSE = 10;

	public const int CERTTYPE_OCSP_REQUEST = 11;

	public const int CERTTYPE_OCSP_RESPONSE = 12;

	public const int CERTTYPE_PKIUSER = 13;

	public const int CERTTYPE_LAST = 14;

	public const int FORMAT_NONE = 0;

	public const int FORMAT_AUTO = 1;

	public const int FORMAT_CRYPTLIB = 2;

	public const int FORMAT_CMS = 3;

	public const int FORMAT_PKCS7 = 3;

	public const int FORMAT_SMIME = 4;

	public const int FORMAT_PGP = 5;

	public const int FORMAT_LAST = 6;

	public const int SESSION_NONE = 0;

	public const int SESSION_SSH = 1;

	public const int SESSION_SSH_SERVER = 2;

	public const int SESSION_SSL = 3;

	public const int SESSION_TLS = 3;

	public const int SESSION_SSL_SERVER = 4;

	public const int SESSION_TLS_SERVER = 4;

	public const int SESSION_RTCS = 5;

	public const int SESSION_RTCS_SERVER = 6;

	public const int SESSION_OCSP = 7;

	public const int SESSION_OCSP_SERVER = 8;

	public const int SESSION_TSP = 9;

	public const int SESSION_TSP_SERVER = 10;

	public const int SESSION_CMP = 11;

	public const int SESSION_CMP_SERVER = 12;

	public const int SESSION_SCEP = 13;

	public const int SESSION_SCEP_SERVER = 14;

	public const int SESSION_CERTSTORE_SERVER = 15;

	public const int SESSION_LAST = 16;

	public const int USER_NONE = 0;

	public const int USER_NORMAL = 1;

	public const int USER_SO = 2;

	public const int USER_CA = 3;

	public const int USER_LAST = 4;

	public const int ATTRIBUTE_NONE = 0;

	public const int PROPERTY_FIRST = 1;

	public const int PROPERTY_HIGHSECURITY = 2;

	public const int PROPERTY_OWNER = 3;

	public const int PROPERTY_FORWARDCOUNT = 4;

	public const int PROPERTY_LOCKED = 5;

	public const int PROPERTY_USAGECOUNT = 6;

	public const int PROPERTY_NONEXPORTABLE = 7;

	public const int PROPERTY_LAST = 8;

	public const int GENERIC_FIRST = 9;

	public const int ATTRIBUTE_ERRORTYPE = 10;

	public const int ATTRIBUTE_ERRORLOCUS = 11;

	public const int ATTRIBUTE_ERRORMESSAGE = 12;

	public const int ATTRIBUTE_CURRENT_GROUP = 13;

	public const int ATTRIBUTE_CURRENT = 14;

	public const int ATTRIBUTE_CURRENT_INSTANCE = 15;

	public const int ATTRIBUTE_BUFFERSIZE = 16;

	public const int GENERIC_LAST = 17;

	public const int OPTION_FIRST = 100;

	public const int OPTION_INFO_DESCRIPTION = 101;

	public const int OPTION_INFO_COPYRIGHT = 102;

	public const int OPTION_INFO_MAJORVERSION = 103;

	public const int OPTION_INFO_MINORVERSION = 104;

	public const int OPTION_INFO_STEPPING = 105;

	public const int OPTION_ENCR_ALGO = 106;

	public const int OPTION_ENCR_HASH = 107;

	public const int OPTION_ENCR_MAC = 108;

	public const int OPTION_PKC_ALGO = 109;

	public const int OPTION_PKC_KEYSIZE = 110;

	public const int OPTION_SIG_ALGO = 111;

	public const int OPTION_SIG_KEYSIZE = 112;

	public const int OPTION_KEYING_ALGO = 113;

	public const int OPTION_KEYING_ITERATIONS = 114;

	public const int OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES = 115;

	public const int OPTION_CERT_VALIDITY = 116;

	public const int OPTION_CERT_UPDATEINTERVAL = 117;

	public const int OPTION_CERT_COMPLIANCELEVEL = 118;

	public const int OPTION_CERT_REQUIREPOLICY = 119;

	public const int OPTION_CMS_DEFAULTATTRIBUTES = 120;

	public const int OPTION_SMIME_DEFAULTATTRIBUTES = 120;

	public const int OPTION_KEYS_LDAP_OBJECTCLASS = 121;

	public const int OPTION_KEYS_LDAP_OBJECTTYPE = 122;

	public const int OPTION_KEYS_LDAP_FILTER = 123;

	public const int OPTION_KEYS_LDAP_CACERTNAME = 124;

	public const int OPTION_KEYS_LDAP_CERTNAME = 125;

	public const int OPTION_KEYS_LDAP_CRLNAME = 126;

	public const int OPTION_KEYS_LDAP_EMAILNAME = 127;

	public const int OPTION_DEVICE_PKCS11_DVR01 = 128;

	public const int OPTION_DEVICE_PKCS11_DVR02 = 129;

	public const int OPTION_DEVICE_PKCS11_DVR03 = 130;

	public const int OPTION_DEVICE_PKCS11_DVR04 = 131;

	public const int OPTION_DEVICE_PKCS11_DVR05 = 132;

	public const int OPTION_DEVICE_PKCS11_HARDWAREONLY = 133;

	public const int OPTION_NET_SOCKS_SERVER = 134;

	public const int OPTION_NET_SOCKS_USERNAME = 135;

	public const int OPTION_NET_HTTP_PROXY = 136;

	public const int OPTION_NET_CONNECTTIMEOUT = 137;

	public const int OPTION_NET_READTIMEOUT = 138;

	public const int OPTION_NET_WRITETIMEOUT = 139;

	public const int OPTION_MISC_ASYNCINIT = 140;

	public const int OPTION_MISC_SIDECHANNELPROTECTION = 141;

	public const int OPTION_CONFIGCHANGED = 142;

	public const int OPTION_SELFTESTOK = 143;

	public const int OPTION_LAST = 144;

	public const int CTXINFO_FIRST = 1000;

	public const int CTXINFO_ALGO = 1001;

	public const int CTXINFO_MODE = 1002;

	public const int CTXINFO_NAME_ALGO = 1003;

	public const int CTXINFO_NAME_MODE = 1004;

	public const int CTXINFO_KEYSIZE = 1005;

	public const int CTXINFO_BLOCKSIZE = 1006;

	public const int CTXINFO_IVSIZE = 1007;

	public const int CTXINFO_KEYING_ALGO = 1008;

	public const int CTXINFO_KEYING_ITERATIONS = 1009;

	public const int CTXINFO_KEYING_SALT = 1010;

	public const int CTXINFO_KEYING_VALUE = 1011;

	public const int CTXINFO_KEY = 1012;

	public const int CTXINFO_KEY_COMPONENTS = 1013;

	public const int CTXINFO_IV = 1014;

	public const int CTXINFO_HASHVALUE = 1015;

	public const int CTXINFO_LABEL = 1016;

	public const int CTXINFO_PERSISTENT = 1017;

	public const int CTXINFO_LAST = 1018;

	public const int CERTINFO_FIRST = 2000;

	public const int CERTINFO_SELFSIGNED = 2001;

	public const int CERTINFO_IMMUTABLE = 2002;

	public const int CERTINFO_XYZZY = 2003;

	public const int CERTINFO_CERTTYPE = 2004;

	public const int CERTINFO_FINGERPRINT_SHA1 = 2005;

	public const int CERTINFO_FINGERPRINT_SHA2 = 2006;

	public const int CERTINFO_FINGERPRINT_SHAng = 2007;

	public const int CERTINFO_CURRENT_CERTIFICATE = 2008;

	public const int CERTINFO_TRUSTED_USAGE = 2009;

	public const int CERTINFO_TRUSTED_IMPLICIT = 2010;

	public const int CERTINFO_SIGNATURELEVEL = 2011;

	public const int CERTINFO_VERSION = 2012;

	public const int CERTINFO_SERIALNUMBER = 2013;

	public const int CERTINFO_SUBJECTPUBLICKEYINFO = 2014;

	public const int CERTINFO_CERTIFICATE = 2015;

	public const int CERTINFO_USERCERTIFICATE = 2015;

	public const int CERTINFO_CACERTIFICATE = 2016;

	public const int CERTINFO_ISSUERNAME = 2017;

	public const int CERTINFO_VALIDFROM = 2018;

	public const int CERTINFO_VALIDTO = 2019;

	public const int CERTINFO_SUBJECTNAME = 2020;

	public const int CERTINFO_ISSUERUNIQUEID = 2021;

	public const int CERTINFO_SUBJECTUNIQUEID = 2022;

	public const int CERTINFO_CERTREQUEST = 2023;

	public const int CERTINFO_THISUPDATE = 2024;

	public const int CERTINFO_NEXTUPDATE = 2025;

	public const int CERTINFO_REVOCATIONDATE = 2026;

	public const int CERTINFO_REVOCATIONSTATUS = 2027;

	public const int CERTINFO_CERTSTATUS = 2028;

	public const int CERTINFO_DN = 2029;

	public const int CERTINFO_PKIUSER_ID = 2030;

	public const int CERTINFO_PKIUSER_ISSUEPASSWORD = 2031;

	public const int CERTINFO_PKIUSER_REVPASSWORD = 2032;

	public const int CERTINFO_PKIUSER_RA = 2033;

	public const int CERTINFO_COUNTRYNAME = 2100;

	public const int CERTINFO_STATEORPROVINCENAME = 2101;

	public const int CERTINFO_LOCALITYNAME = 2102;

	public const int CERTINFO_ORGANIZATIONNAME = 2103;

	public const int CERTINFO_ORGANISATIONNAME = 2103;

	public const int CERTINFO_ORGANIZATIONALUNITNAME = 2104;

	public const int CERTINFO_ORGANISATIONALUNITNAME = 2104;

	public const int CERTINFO_COMMONNAME = 2105;

	public const int CERTINFO_OTHERNAME_TYPEID = 2106;

	public const int CERTINFO_OTHERNAME_VALUE = 2107;

	public const int CERTINFO_RFC822NAME = 2108;

	public const int CERTINFO_EMAIL = 2108;

	public const int CERTINFO_DNSNAME = 2109;

	public const int CERTINFO_DIRECTORYNAME = 2110;

	public const int CERTINFO_EDIPARTYNAME_NAMEASSIGNER = 2111;

	public const int CERTINFO_EDIPARTYNAME_PARTYNAME = 2112;

	public const int CERTINFO_UNIFORMRESOURCEIDENTIFIER = 2113;

	public const int CERTINFO_URL = 2113;

	public const int CERTINFO_IPADDRESS = 2114;

	public const int CERTINFO_REGISTEREDID = 2115;

	public const int CERTINFO_CHALLENGEPASSWORD = 2200;

	public const int CERTINFO_CRLEXTREASON = 2201;

	public const int CERTINFO_KEYFEATURES = 2202;

	public const int CERTINFO_AUTHORITYINFOACCESS = 2203;

	public const int CERTINFO_AUTHORITYINFO_RTCS = 2204;

	public const int CERTINFO_AUTHORITYINFO_OCSP = 2205;

	public const int CERTINFO_AUTHORITYINFO_CAISSUERS = 2206;

	public const int CERTINFO_AUTHORITYINFO_CERTSTORE = 2207;

	public const int CERTINFO_AUTHORITYINFO_CRLS = 2208;

	public const int CERTINFO_BIOMETRICINFO = 2209;

	public const int CERTINFO_BIOMETRICINFO_TYPE = 2210;

	public const int CERTINFO_BIOMETRICINFO_HASHALGO = 2211;

	public const int CERTINFO_BIOMETRICINFO_HASH = 2212;

	public const int CERTINFO_BIOMETRICINFO_URL = 2213;

	public const int CERTINFO_QCSTATEMENT = 2214;

	public const int CERTINFO_QCSTATEMENT_SEMANTICS = 2215;

	public const int CERTINFO_QCSTATEMENT_REGISTRATIONAUTHORITY = 2216;

	public const int CERTINFO_IPADDRESSBLOCKS = 2217;

	public const int CERTINFO_IPADDRESSBLOCKS_ADDRESSFAMILY = 2218;

	public const int CERTINFO_IPADDRESSBLOCKS_PREFIX = 2219;

	public const int CERTINFO_IPADDRESSBLOCKS_MIN = 2220;

	public const int CERTINFO_IPADDRESSBLOCKS_MAX = 2221;

	public const int CERTINFO_AUTONOMOUSSYSIDS = 2222;

	public const int CERTINFO_AUTONOMOUSSYSIDS_ASNUM_ID = 2223;

	public const int CERTINFO_AUTONOMOUSSYSIDS_ASNUM_MIN = 2224;

	public const int CERTINFO_AUTONOMOUSSYSIDS_ASNUM_MAX = 2225;

	public const int CERTINFO_OCSP_NONCE = 2226;

	public const int CERTINFO_OCSP_RESPONSE = 2227;

	public const int CERTINFO_OCSP_RESPONSE_OCSP = 2228;

	public const int CERTINFO_OCSP_NOCHECK = 2229;

	public const int CERTINFO_OCSP_ARCHIVECUTOFF = 2230;

	public const int CERTINFO_SUBJECTINFOACCESS = 2231;

	public const int CERTINFO_SUBJECTINFO_TIMESTAMPING = 2232;

	public const int CERTINFO_SUBJECTINFO_CAREPOSITORY = 2233;

	public const int CERTINFO_SUBJECTINFO_SIGNEDOBJECTREPOSITORY = 2234;

	public const int CERTINFO_SUBJECTINFO_RPKIMANIFEST = 2235;

	public const int CERTINFO_SUBJECTINFO_SIGNEDOBJECT = 2236;

	public const int CERTINFO_SIGG_DATEOFCERTGEN = 2237;

	public const int CERTINFO_SIGG_PROCURATION = 2238;

	public const int CERTINFO_SIGG_PROCURE_COUNTRY = 2239;

	public const int CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION = 2240;

	public const int CERTINFO_SIGG_PROCURE_SIGNINGFOR = 2241;

	public const int CERTINFO_SIGG_ADMISSIONS = 2242;

	public const int CERTINFO_SIGG_ADMISSIONS_AUTHORITY = 2243;

	public const int CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHID = 2244;

	public const int CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHURL = 2245;

	public const int CERTINFO_SIGG_ADMISSIONS_NAMINGAUTHTEXT = 2246;

	public const int CERTINFO_SIGG_ADMISSIONS_PROFESSIONITEM = 2247;

	public const int CERTINFO_SIGG_ADMISSIONS_PROFESSIONOID = 2248;

	public const int CERTINFO_SIGG_ADMISSIONS_REGISTRATIONNUMBER = 2249;

	public const int CERTINFO_SIGG_MONETARYLIMIT = 2250;

	public const int CERTINFO_SIGG_MONETARY_CURRENCY = 2251;

	public const int CERTINFO_SIGG_MONETARY_AMOUNT = 2252;

	public const int CERTINFO_SIGG_MONETARY_EXPONENT = 2253;

	public const int CERTINFO_SIGG_DECLARATIONOFMAJORITY = 2254;

	public const int CERTINFO_SIGG_DECLARATIONOFMAJORITY_COUNTRY = 2255;

	public const int CERTINFO_SIGG_RESTRICTION = 2256;

	public const int CERTINFO_SIGG_CERTHASH = 2257;

	public const int CERTINFO_SIGG_ADDITIONALINFORMATION = 2258;

	public const int CERTINFO_STRONGEXTRANET = 2259;

	public const int CERTINFO_STRONGEXTRANET_ZONE = 2260;

	public const int CERTINFO_STRONGEXTRANET_ID = 2261;

	public const int CERTINFO_SUBJECTDIRECTORYATTRIBUTES = 2262;

	public const int CERTINFO_SUBJECTDIR_TYPE = 2263;

	public const int CERTINFO_SUBJECTDIR_VALUES = 2264;

	public const int CERTINFO_SUBJECTKEYIDENTIFIER = 2265;

	public const int CERTINFO_KEYUSAGE = 2266;

	public const int CERTINFO_PRIVATEKEYUSAGEPERIOD = 2267;

	public const int CERTINFO_PRIVATEKEY_NOTBEFORE = 2268;

	public const int CERTINFO_PRIVATEKEY_NOTAFTER = 2269;

	public const int CERTINFO_SUBJECTALTNAME = 2270;

	public const int CERTINFO_ISSUERALTNAME = 2271;

	public const int CERTINFO_BASICCONSTRAINTS = 2272;

	public const int CERTINFO_CA = 2273;

	public const int CERTINFO_AUTHORITY = 2273;

	public const int CERTINFO_PATHLENCONSTRAINT = 2274;

	public const int CERTINFO_CRLNUMBER = 2275;

	public const int CERTINFO_CRLREASON = 2276;

	public const int CERTINFO_HOLDINSTRUCTIONCODE = 2277;

	public const int CERTINFO_INVALIDITYDATE = 2278;

	public const int CERTINFO_DELTACRLINDICATOR = 2279;

	public const int CERTINFO_ISSUINGDISTRIBUTIONPOINT = 2280;

	public const int CERTINFO_ISSUINGDIST_FULLNAME = 2281;

	public const int CERTINFO_ISSUINGDIST_USERCERTSONLY = 2282;

	public const int CERTINFO_ISSUINGDIST_CACERTSONLY = 2283;

	public const int CERTINFO_ISSUINGDIST_SOMEREASONSONLY = 2284;

	public const int CERTINFO_ISSUINGDIST_INDIRECTCRL = 2285;

	public const int CERTINFO_CERTIFICATEISSUER = 2286;

	public const int CERTINFO_NAMECONSTRAINTS = 2287;

	public const int CERTINFO_PERMITTEDSUBTREES = 2288;

	public const int CERTINFO_EXCLUDEDSUBTREES = 2289;

	public const int CERTINFO_CRLDISTRIBUTIONPOINT = 2290;

	public const int CERTINFO_CRLDIST_FULLNAME = 2291;

	public const int CERTINFO_CRLDIST_REASONS = 2292;

	public const int CERTINFO_CRLDIST_CRLISSUER = 2293;

	public const int CERTINFO_CERTIFICATEPOLICIES = 2294;

	public const int CERTINFO_CERTPOLICYID = 2295;

	public const int CERTINFO_CERTPOLICY_CPSURI = 2296;

	public const int CERTINFO_CERTPOLICY_ORGANIZATION = 2297;

	public const int CERTINFO_CERTPOLICY_NOTICENUMBERS = 2298;

	public const int CERTINFO_CERTPOLICY_EXPLICITTEXT = 2299;

	public const int CERTINFO_POLICYMAPPINGS = 2300;

	public const int CERTINFO_ISSUERDOMAINPOLICY = 2301;

	public const int CERTINFO_SUBJECTDOMAINPOLICY = 2302;

	public const int CERTINFO_AUTHORITYKEYIDENTIFIER = 2303;

	public const int CERTINFO_AUTHORITY_KEYIDENTIFIER = 2304;

	public const int CERTINFO_AUTHORITY_CERTISSUER = 2305;

	public const int CERTINFO_AUTHORITY_CERTSERIALNUMBER = 2306;

	public const int CERTINFO_POLICYCONSTRAINTS = 2307;

	public const int CERTINFO_REQUIREEXPLICITPOLICY = 2308;

	public const int CERTINFO_INHIBITPOLICYMAPPING = 2309;

	public const int CERTINFO_EXTKEYUSAGE = 2310;

	public const int CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING = 2311;

	public const int CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING = 2312;

	public const int CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING = 2313;

	public const int CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING = 2314;

	public const int CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO = 2315;

	public const int CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM = 2316;

	public const int CERTINFO_EXTKEY_SERVERAUTH = 2317;

	public const int CERTINFO_EXTKEY_CLIENTAUTH = 2318;

	public const int CERTINFO_EXTKEY_CODESIGNING = 2319;

	public const int CERTINFO_EXTKEY_EMAILPROTECTION = 2320;

	public const int CERTINFO_EXTKEY_IPSECENDSYSTEM = 2321;

	public const int CERTINFO_EXTKEY_IPSECTUNNEL = 2322;

	public const int CERTINFO_EXTKEY_IPSECUSER = 2323;

	public const int CERTINFO_EXTKEY_TIMESTAMPING = 2324;

	public const int CERTINFO_EXTKEY_OCSPSIGNING = 2325;

	public const int CERTINFO_EXTKEY_DIRECTORYSERVICE = 2326;

	public const int CERTINFO_EXTKEY_ANYKEYUSAGE = 2327;

	public const int CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO = 2328;

	public const int CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA = 2329;

	public const int CERTINFO_CRLSTREAMIDENTIFIER = 2330;

	public const int CERTINFO_FRESHESTCRL = 2331;

	public const int CERTINFO_FRESHESTCRL_FULLNAME = 2332;

	public const int CERTINFO_FRESHESTCRL_REASONS = 2333;

	public const int CERTINFO_FRESHESTCRL_CRLISSUER = 2334;

	public const int CERTINFO_ORDEREDLIST = 2335;

	public const int CERTINFO_BASEUPDATETIME = 2336;

	public const int CERTINFO_DELTAINFO = 2337;

	public const int CERTINFO_DELTAINFO_LOCATION = 2338;

	public const int CERTINFO_DELTAINFO_NEXTDELTA = 2339;

	public const int CERTINFO_INHIBITANYPOLICY = 2340;

	public const int CERTINFO_TOBEREVOKED = 2341;

	public const int CERTINFO_TOBEREVOKED_CERTISSUER = 2342;

	public const int CERTINFO_TOBEREVOKED_REASONCODE = 2343;

	public const int CERTINFO_TOBEREVOKED_REVOCATIONTIME = 2344;

	public const int CERTINFO_TOBEREVOKED_CERTSERIALNUMBER = 2345;

	public const int CERTINFO_REVOKEDGROUPS = 2346;

	public const int CERTINFO_REVOKEDGROUPS_CERTISSUER = 2347;

	public const int CERTINFO_REVOKEDGROUPS_REASONCODE = 2348;

	public const int CERTINFO_REVOKEDGROUPS_INVALIDITYDATE = 2349;

	public const int CERTINFO_REVOKEDGROUPS_STARTINGNUMBER = 2350;

	public const int CERTINFO_REVOKEDGROUPS_ENDINGNUMBER = 2351;

	public const int CERTINFO_EXPIREDCERTSONCRL = 2352;

	public const int CERTINFO_AAISSUINGDISTRIBUTIONPOINT = 2353;

	public const int CERTINFO_AAISSUINGDIST_FULLNAME = 2354;

	public const int CERTINFO_AAISSUINGDIST_SOMEREASONSONLY = 2355;

	public const int CERTINFO_AAISSUINGDIST_INDIRECTCRL = 2356;

	public const int CERTINFO_AAISSUINGDIST_USERATTRCERTS = 2357;

	public const int CERTINFO_AAISSUINGDIST_AACERTS = 2358;

	public const int CERTINFO_AAISSUINGDIST_SOACERTS = 2359;

	public const int CERTINFO_NS_CERTTYPE = 2360;

	public const int CERTINFO_NS_BASEURL = 2361;

	public const int CERTINFO_NS_REVOCATIONURL = 2362;

	public const int CERTINFO_NS_CAREVOCATIONURL = 2363;

	public const int CERTINFO_NS_CERTRENEWALURL = 2364;

	public const int CERTINFO_NS_CAPOLICYURL = 2365;

	public const int CERTINFO_NS_SSLSERVERNAME = 2366;

	public const int CERTINFO_NS_COMMENT = 2367;

	public const int CERTINFO_SET_HASHEDROOTKEY = 2368;

	public const int CERTINFO_SET_ROOTKEYTHUMBPRINT = 2369;

	public const int CERTINFO_SET_CERTIFICATETYPE = 2370;

	public const int CERTINFO_SET_MERCHANTDATA = 2371;

	public const int CERTINFO_SET_MERID = 2372;

	public const int CERTINFO_SET_MERACQUIRERBIN = 2373;

	public const int CERTINFO_SET_MERCHANTLANGUAGE = 2374;

	public const int CERTINFO_SET_MERCHANTNAME = 2375;

	public const int CERTINFO_SET_MERCHANTCITY = 2376;

	public const int CERTINFO_SET_MERCHANTSTATEPROVINCE = 2377;

	public const int CERTINFO_SET_MERCHANTPOSTALCODE = 2378;

	public const int CERTINFO_SET_MERCHANTCOUNTRYNAME = 2379;

	public const int CERTINFO_SET_MERCOUNTRY = 2380;

	public const int CERTINFO_SET_MERAUTHFLAG = 2381;

	public const int CERTINFO_SET_CERTCARDREQUIRED = 2382;

	public const int CERTINFO_SET_TUNNELING = 2383;

	public const int CERTINFO_SET_TUNNELLING = 2383;

	public const int CERTINFO_SET_TUNNELINGFLAG = 2384;

	public const int CERTINFO_SET_TUNNELLINGFLAG = 2384;

	public const int CERTINFO_SET_TUNNELINGALGID = 2385;

	public const int CERTINFO_SET_TUNNELLINGALGID = 2385;

	public const int CERTINFO_CMS_CONTENTTYPE = 2500;

	public const int CERTINFO_CMS_MESSAGEDIGEST = 2501;

	public const int CERTINFO_CMS_SIGNINGTIME = 2502;

	public const int CERTINFO_CMS_COUNTERSIGNATURE = 2503;

	public const int CERTINFO_CMS_SIGNINGDESCRIPTION = 2504;

	public const int CERTINFO_CMS_SMIMECAPABILITIES = 2505;

	public const int CERTINFO_CMS_SMIMECAP_3DES = 2506;

	public const int CERTINFO_CMS_SMIMECAP_AES = 2507;

	public const int CERTINFO_CMS_SMIMECAP_CAST128 = 2508;

	public const int CERTINFO_CMS_SMIMECAP_SHAng = 2509;

	public const int CERTINFO_CMS_SMIMECAP_SHA2 = 2510;

	public const int CERTINFO_CMS_SMIMECAP_SHA1 = 2511;

	public const int CERTINFO_CMS_SMIMECAP_HMAC_SHAng = 2512;

	public const int CERTINFO_CMS_SMIMECAP_HMAC_SHA2 = 2513;

	public const int CERTINFO_CMS_SMIMECAP_HMAC_SHA1 = 2514;

	public const int CERTINFO_CMS_SMIMECAP_AUTHENC256 = 2515;

	public const int CERTINFO_CMS_SMIMECAP_AUTHENC128 = 2516;

	public const int CERTINFO_CMS_SMIMECAP_RSA_SHAng = 2517;

	public const int CERTINFO_CMS_SMIMECAP_RSA_SHA2 = 2518;

	public const int CERTINFO_CMS_SMIMECAP_RSA_SHA1 = 2519;

	public const int CERTINFO_CMS_SMIMECAP_DSA_SHA1 = 2520;

	public const int CERTINFO_CMS_SMIMECAP_ECDSA_SHAng = 2521;

	public const int CERTINFO_CMS_SMIMECAP_ECDSA_SHA2 = 2522;

	public const int CERTINFO_CMS_SMIMECAP_ECDSA_SHA1 = 2523;

	public const int CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA = 2524;

	public const int CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY = 2525;

	public const int CERTINFO_CMS_SMIMECAP_PREFERBINARYINSIDE = 2526;

	public const int CERTINFO_CMS_RECEIPTREQUEST = 2527;

	public const int CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER = 2528;

	public const int CERTINFO_CMS_RECEIPT_FROM = 2529;

	public const int CERTINFO_CMS_RECEIPT_TO = 2530;

	public const int CERTINFO_CMS_SECURITYLABEL = 2531;

	public const int CERTINFO_CMS_SECLABEL_POLICY = 2532;

	public const int CERTINFO_CMS_SECLABEL_CLASSIFICATION = 2533;

	public const int CERTINFO_CMS_SECLABEL_PRIVACYMARK = 2534;

	public const int CERTINFO_CMS_SECLABEL_CATTYPE = 2535;

	public const int CERTINFO_CMS_SECLABEL_CATVALUE = 2536;

	public const int CERTINFO_CMS_MLEXPANSIONHISTORY = 2537;

	public const int CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER = 2538;

	public const int CERTINFO_CMS_MLEXP_TIME = 2539;

	public const int CERTINFO_CMS_MLEXP_NONE = 2540;

	public const int CERTINFO_CMS_MLEXP_INSTEADOF = 2541;

	public const int CERTINFO_CMS_MLEXP_INADDITIONTO = 2542;

	public const int CERTINFO_CMS_CONTENTHINTS = 2543;

	public const int CERTINFO_CMS_CONTENTHINT_DESCRIPTION = 2544;

	public const int CERTINFO_CMS_CONTENTHINT_TYPE = 2545;

	public const int CERTINFO_CMS_EQUIVALENTLABEL = 2546;

	public const int CERTINFO_CMS_EQVLABEL_POLICY = 2547;

	public const int CERTINFO_CMS_EQVLABEL_CLASSIFICATION = 2548;

	public const int CERTINFO_CMS_EQVLABEL_PRIVACYMARK = 2549;

	public const int CERTINFO_CMS_EQVLABEL_CATTYPE = 2550;

	public const int CERTINFO_CMS_EQVLABEL_CATVALUE = 2551;

	public const int CERTINFO_CMS_SIGNINGCERTIFICATE = 2552;

	public const int CERTINFO_CMS_SIGNINGCERT_ESSCERTID = 2553;

	public const int CERTINFO_CMS_SIGNINGCERT_POLICIES = 2554;

	public const int CERTINFO_CMS_SIGNINGCERTIFICATEV2 = 2555;

	public const int CERTINFO_CMS_SIGNINGCERTV2_ESSCERTIDV2 = 2556;

	public const int CERTINFO_CMS_SIGNINGCERTV2_POLICIES = 2557;

	public const int CERTINFO_CMS_SIGNATUREPOLICYID = 2558;

	public const int CERTINFO_CMS_SIGPOLICYID = 2559;

	public const int CERTINFO_CMS_SIGPOLICYHASH = 2560;

	public const int CERTINFO_CMS_SIGPOLICY_CPSURI = 2561;

	public const int CERTINFO_CMS_SIGPOLICY_ORGANIZATION = 2562;

	public const int CERTINFO_CMS_SIGPOLICY_NOTICENUMBERS = 2563;

	public const int CERTINFO_CMS_SIGPOLICY_EXPLICITTEXT = 2564;

	public const int CERTINFO_CMS_SIGTYPEIDENTIFIER = 2565;

	public const int CERTINFO_CMS_SIGTYPEID_ORIGINATORSIG = 2566;

	public const int CERTINFO_CMS_SIGTYPEID_DOMAINSIG = 2567;

	public const int CERTINFO_CMS_SIGTYPEID_ADDITIONALATTRIBUTES = 2568;

	public const int CERTINFO_CMS_SIGTYPEID_REVIEWSIG = 2569;

	public const int CERTINFO_CMS_NONCE = 2570;

	public const int CERTINFO_SCEP_MESSAGETYPE = 2571;

	public const int CERTINFO_SCEP_PKISTATUS = 2572;

	public const int CERTINFO_SCEP_FAILINFO = 2573;

	public const int CERTINFO_SCEP_SENDERNONCE = 2574;

	public const int CERTINFO_SCEP_RECIPIENTNONCE = 2575;

	public const int CERTINFO_SCEP_TRANSACTIONID = 2576;

	public const int CERTINFO_CMS_SPCAGENCYINFO = 2577;

	public const int CERTINFO_CMS_SPCAGENCYURL = 2578;

	public const int CERTINFO_CMS_SPCSTATEMENTTYPE = 2579;

	public const int CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING = 2580;

	public const int CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING = 2581;

	public const int CERTINFO_CMS_SPCOPUSINFO = 2582;

	public const int CERTINFO_CMS_SPCOPUSINFO_NAME = 2583;

	public const int CERTINFO_CMS_SPCOPUSINFO_URL = 2584;

	public const int CERTINFO_LAST = 2585;

	public const int KEYINFO_FIRST = 3000;

	public const int KEYINFO_QUERY = 3001;

	public const int KEYINFO_QUERY_REQUESTS = 3002;

	public const int KEYINFO_LAST = 3003;

	public const int DEVINFO_FIRST = 4000;

	public const int DEVINFO_INITIALISE = 4001;

	public const int DEVINFO_INITIALIZE = 4001;

	public const int DEVINFO_AUTHENT_USER = 4002;

	public const int DEVINFO_AUTHENT_SUPERVISOR = 4003;

	public const int DEVINFO_SET_AUTHENT_USER = 4004;

	public const int DEVINFO_SET_AUTHENT_SUPERVISOR = 4005;

	public const int DEVINFO_ZEROISE = 4006;

	public const int DEVINFO_ZEROIZE = 4006;

	public const int DEVINFO_LOGGEDIN = 4007;

	public const int DEVINFO_LABEL = 4008;

	public const int DEVINFO_LAST = 4009;

	public const int ENVINFO_FIRST = 5000;

	public const int ENVINFO_DATASIZE = 5001;

	public const int ENVINFO_COMPRESSION = 5002;

	public const int ENVINFO_CONTENTTYPE = 5003;

	public const int ENVINFO_DETACHEDSIGNATURE = 5004;

	public const int ENVINFO_SIGNATURE_RESULT = 5005;

	public const int ENVINFO_INTEGRITY = 5006;

	public const int ENVINFO_PASSWORD = 5007;

	public const int ENVINFO_KEY = 5008;

	public const int ENVINFO_SIGNATURE = 5009;

	public const int ENVINFO_SIGNATURE_EXTRADATA = 5010;

	public const int ENVINFO_RECIPIENT = 5011;

	public const int ENVINFO_PUBLICKEY = 5012;

	public const int ENVINFO_PRIVATEKEY = 5013;

	public const int ENVINFO_PRIVATEKEY_LABEL = 5014;

	public const int ENVINFO_ORIGINATOR = 5015;

	public const int ENVINFO_SESSIONKEY = 5016;

	public const int ENVINFO_HASH = 5017;

	public const int ENVINFO_TIMESTAMP = 5018;

	public const int ENVINFO_KEYSET_SIGCHECK = 5019;

	public const int ENVINFO_KEYSET_ENCRYPT = 5020;

	public const int ENVINFO_KEYSET_DECRYPT = 5021;

	public const int ENVINFO_LAST = 5022;

	public const int SESSINFO_FIRST = 6000;

	public const int SESSINFO_ACTIVE = 6001;

	public const int SESSINFO_CONNECTIONACTIVE = 6002;

	public const int SESSINFO_USERNAME = 6003;

	public const int SESSINFO_PASSWORD = 6004;

	public const int SESSINFO_PRIVATEKEY = 6005;

	public const int SESSINFO_KEYSET = 6006;

	public const int SESSINFO_AUTHRESPONSE = 6007;

	public const int SESSINFO_SERVER_NAME = 6008;

	public const int SESSINFO_SERVER_PORT = 6009;

	public const int SESSINFO_SERVER_FINGERPRINT_SHA1 = 6010;

	public const int SESSINFO_CLIENT_NAME = 6011;

	public const int SESSINFO_CLIENT_PORT = 6012;

	public const int SESSINFO_SESSION = 6013;

	public const int SESSINFO_NETWORKSOCKET = 6014;

	public const int SESSINFO_VERSION = 6015;

	public const int SESSINFO_REQUEST = 6016;

	public const int SESSINFO_RESPONSE = 6017;

	public const int SESSINFO_CACERTIFICATE = 6018;

	public const int SESSINFO_CMP_REQUESTTYPE = 6019;

	public const int SESSINFO_CMP_PRIVKEYSET = 6020;

	public const int SESSINFO_SSH_CHANNEL = 6021;

	public const int SESSINFO_SSH_CHANNEL_TYPE = 6022;

	public const int SESSINFO_SSH_CHANNEL_ARG1 = 6023;

	public const int SESSINFO_SSH_CHANNEL_ARG2 = 6024;

	public const int SESSINFO_SSH_CHANNEL_ACTIVE = 6025;

	public const int SESSINFO_SSL_OPTIONS = 6026;

	public const int SESSINFO_TSP_MSGIMPRINT = 6027;

	public const int SESSINFO_LAST = 6028;

	public const int USERINFO_FIRST = 7000;

	public const int USERINFO_PASSWORD = 7001;

	public const int USERINFO_CAKEY_CERTSIGN = 7002;

	public const int USERINFO_CAKEY_CRLSIGN = 7003;

	public const int USERINFO_CAKEY_RTCSSIGN = 7004;

	public const int USERINFO_CAKEY_OCSPSIGN = 7005;

	public const int USERINFO_LAST = 7006;

	public const int ATTRIBUTE_LAST = 7006;

	public const int KEYUSAGE_NONE = 0;

	public const int KEYUSAGE_DIGITALSIGNATURE = 1;

	public const int KEYUSAGE_NONREPUDIATION = 2;

	public const int KEYUSAGE_KEYENCIPHERMENT = 4;

	public const int KEYUSAGE_DATAENCIPHERMENT = 8;

	public const int KEYUSAGE_KEYAGREEMENT = 16;

	public const int KEYUSAGE_KEYCERTSIGN = 32;

	public const int KEYUSAGE_CRLSIGN = 64;

	public const int KEYUSAGE_ENCIPHERONLY = 128;

	public const int KEYUSAGE_DECIPHERONLY = 256;

	public const int KEYUSAGE_LAST = 512;

	public const int CRLREASON_UNSPECIFIED = 0;

	public const int CRLREASON_KEYCOMPROMISE = 1;

	public const int CRLREASON_CACOMPROMISE = 2;

	public const int CRLREASON_AFFILIATIONCHANGED = 3;

	public const int CRLREASON_SUPERSEDED = 4;

	public const int CRLREASON_CESSATIONOFOPERATION = 5;

	public const int CRLREASON_CERTIFICATEHOLD = 6;

	public const int CRLREASON_REMOVEFROMCRL = 8;

	public const int CRLREASON_PRIVILEGEWITHDRAWN = 9;

	public const int CRLREASON_AACOMPROMISE = 10;

	public const int CRLREASON_LAST = 11;

	public const int CRLREASON_NEVERVALID = 20;

	public const int CRLEXTREASON_LAST = 21;

	public const int CRLREASONFLAG_UNUSED = 1;

	public const int CRLREASONFLAG_KEYCOMPROMISE = 2;

	public const int CRLREASONFLAG_CACOMPROMISE = 4;

	public const int CRLREASONFLAG_AFFILIATIONCHANGED = 8;

	public const int CRLREASONFLAG_SUPERSEDED = 16;

	public const int CRLREASONFLAG_CESSATIONOFOPERATION = 32;

	public const int CRLREASONFLAG_CERTIFICATEHOLD = 64;

	public const int CRLREASONFLAG_LAST = 128;

	public const int HOLDINSTRUCTION_NONE = 0;

	public const int HOLDINSTRUCTION_CALLISSUER = 1;

	public const int HOLDINSTRUCTION_REJECT = 2;

	public const int HOLDINSTRUCTION_PICKUPTOKEN = 3;

	public const int HOLDINSTRUCTION_LAST = 4;

	public const int COMPLIANCELEVEL_OBLIVIOUS = 0;

	public const int COMPLIANCELEVEL_REDUCED = 1;

	public const int COMPLIANCELEVEL_STANDARD = 2;

	public const int COMPLIANCELEVEL_PKIX_PARTIAL = 3;

	public const int COMPLIANCELEVEL_PKIX_FULL = 4;

	public const int COMPLIANCELEVEL_LAST = 5;

	public const int NS_CERTTYPE_SSLCLIENT = 1;

	public const int NS_CERTTYPE_SSLSERVER = 2;

	public const int NS_CERTTYPE_SMIME = 4;

	public const int NS_CERTTYPE_OBJECTSIGNING = 8;

	public const int NS_CERTTYPE_RESERVED = 16;

	public const int NS_CERTTYPE_SSLCA = 32;

	public const int NS_CERTTYPE_SMIMECA = 64;

	public const int NS_CERTTYPE_OBJECTSIGNINGCA = 128;

	public const int NS_CERTTYPE_LAST = 256;

	public const int SET_CERTTYPE_CARD = 1;

	public const int SET_CERTTYPE_MER = 2;

	public const int SET_CERTTYPE_PGWY = 4;

	public const int SET_CERTTYPE_CCA = 8;

	public const int SET_CERTTYPE_MCA = 16;

	public const int SET_CERTTYPE_PCA = 32;

	public const int SET_CERTTYPE_GCA = 64;

	public const int SET_CERTTYPE_BCA = 128;

	public const int SET_CERTTYPE_RCA = 256;

	public const int SET_CERTTYPE_ACQ = 512;

	public const int SET_CERTTYPE_LAST = 1024;

	public const int CONTENT_NONE = 0;

	public const int CONTENT_DATA = 1;

	public const int CONTENT_SIGNEDDATA = 2;

	public const int CONTENT_ENVELOPEDDATA = 3;

	public const int CONTENT_SIGNEDANDENVELOPEDDATA = 4;

	public const int CONTENT_DIGESTEDDATA = 5;

	public const int CONTENT_ENCRYPTEDDATA = 6;

	public const int CONTENT_COMPRESSEDDATA = 7;

	public const int CONTENT_AUTHDATA = 8;

	public const int CONTENT_AUTHENVDATA = 9;

	public const int CONTENT_TSTINFO = 10;

	public const int CONTENT_SPCINDIRECTDATACONTEXT = 11;

	public const int CONTENT_RTCSREQUEST = 12;

	public const int CONTENT_RTCSRESPONSE = 13;

	public const int CONTENT_RTCSRESPONSE_EXT = 14;

	public const int CONTENT_MRTD = 15;

	public const int CONTENT_LAST = 16;

	public const int CLASSIFICATION_UNMARKED = 0;

	public const int CLASSIFICATION_UNCLASSIFIED = 1;

	public const int CLASSIFICATION_RESTRICTED = 2;

	public const int CLASSIFICATION_CONFIDENTIAL = 3;

	public const int CLASSIFICATION_SECRET = 4;

	public const int CLASSIFICATION_TOP_SECRET = 5;

	public const int CLASSIFICATION_LAST = 255;

	public const int CERTSTATUS_VALID = 0;

	public const int CERTSTATUS_NOTVALID = 1;

	public const int CERTSTATUS_NONAUTHORITATIVE = 2;

	public const int CERTSTATUS_UNKNOWN = 3;

	public const int OCSPSTATUS_NOTREVOKED = 0;

	public const int OCSPSTATUS_REVOKED = 1;

	public const int OCSPSTATUS_UNKNOWN = 2;

	public const int SIGNATURELEVEL_NONE = 0;

	public const int SIGNATURELEVEL_SIGNERCERT = 1;

	public const int SIGNATURELEVEL_ALL = 2;

	public const int SIGNATURELEVEL_LAST = 3;

	public const int INTEGRITY_NONE = 0;

	public const int INTEGRITY_MACONLY = 1;

	public const int INTEGRITY_FULL = 2;

	public const int CERTFORMAT_NONE = 0;

	public const int CERTFORMAT_CERTIFICATE = 1;

	public const int CERTFORMAT_CERTCHAIN = 2;

	public const int CERTFORMAT_TEXT_CERTIFICATE = 3;

	public const int CERTFORMAT_TEXT_CERTCHAIN = 4;

	public const int CERTFORMAT_XML_CERTIFICATE = 5;

	public const int CERTFORMAT_XML_CERTCHAIN = 6;

	public const int CERTFORMAT_LAST = 7;

	public const int REQUESTTYPE_NONE = 0;

	public const int REQUESTTYPE_INITIALISATION = 1;

	public const int REQUESTTYPE_INITIALIZATION = 1;

	public const int REQUESTTYPE_CERTIFICATE = 2;

	public const int REQUESTTYPE_KEYUPDATE = 3;

	public const int REQUESTTYPE_REVOCATION = 4;

	public const int REQUESTTYPE_PKIBOOT = 5;

	public const int REQUESTTYPE_LAST = 6;

	public const int KEYID_NONE = 0;

	public const int KEYID_NAME = 1;

	public const int KEYID_URI = 2;

	public const int KEYID_EMAIL = 2;

	public const int KEYID_LAST = 3;

	public const int OBJECT_NONE = 0;

	public const int OBJECT_ENCRYPTED_KEY = 1;

	public const int OBJECT_PKCENCRYPTED_KEY = 2;

	public const int OBJECT_KEYAGREEMENT = 3;

	public const int OBJECT_SIGNATURE = 4;

	public const int OBJECT_LAST = 5;

	public const int ERRTYPE_NONE = 0;

	public const int ERRTYPE_ATTR_SIZE = 1;

	public const int ERRTYPE_ATTR_VALUE = 2;

	public const int ERRTYPE_ATTR_ABSENT = 3;

	public const int ERRTYPE_ATTR_PRESENT = 4;

	public const int ERRTYPE_CONSTRAINT = 5;

	public const int ERRTYPE_ISSUERCONSTRAINT = 6;

	public const int ERRTYPE_LAST = 7;

	public const int CERTACTION_NONE = 0;

	public const int CERTACTION_CREATE = 1;

	public const int CERTACTION_CONNECT = 2;

	public const int CERTACTION_DISCONNECT = 3;

	public const int CERTACTION_ERROR = 4;

	public const int CERTACTION_ADDUSER = 5;

	public const int CERTACTION_DELETEUSER = 6;

	public const int CERTACTION_REQUEST_CERT = 7;

	public const int CERTACTION_REQUEST_RENEWAL = 8;

	public const int CERTACTION_REQUEST_REVOCATION = 9;

	public const int CERTACTION_CERT_CREATION = 10;

	public const int CERTACTION_CERT_CREATION_COMPLETE = 11;

	public const int CERTACTION_CERT_CREATION_DROP = 12;

	public const int CERTACTION_CERT_CREATION_REVERSE = 13;

	public const int CERTACTION_RESTART_CLEANUP = 14;

	public const int CERTACTION_RESTART_REVOKE_CERT = 15;

	public const int CERTACTION_ISSUE_CERT = 16;

	public const int CERTACTION_ISSUE_CRL = 17;

	public const int CERTACTION_REVOKE_CERT = 18;

	public const int CERTACTION_EXPIRE_CERT = 19;

	public const int CERTACTION_CLEANUP = 20;

	public const int CERTACTION_LAST = 21;

	public const int SSLOPTION_NONE = 0;

	public const int SSLOPTION_MINVER_SSLV3 = 0;

	public const int SSLOPTION_MINVER_TLS10 = 1;

	public const int SSLOPTION_MINVER_TLS11 = 2;

	public const int SSLOPTION_MINVER_TLS12 = 3;

	public const int SSLOPTION_MINVER_TLS13 = 4;

	public const int SSLOPTION_MANUAL_CERTCHECK = 8;

	public const int SSLOPTION_DISABLE_NAMEVERIFY = 16;

	public const int SSLOPTION_DISABLE_CERTVERIFY = 32;

	public const int SSLOPTION_SUITEB_128 = 256;

	public const int SSLOPTION_SUITEB_256 = 512;

	public const int MAX_KEYSIZE = 256;

	public const int MAX_IVSIZE = 32;

	public const int MAX_PKCSIZE = 512;

	public const int MAX_PKCSIZE_ECC = 72;

	public const int MAX_HASHSIZE = 64;

	public const int MAX_TEXTSIZE = 64;

	public const int USE_DEFAULT = -100;

	public const int UNUSED = -101;

	public const int CURSOR_FIRST = -200;

	public const int CURSOR_PREVIOUS = -201;

	public const int CURSOR_NEXT = -202;

	public const int CURSOR_LAST = -203;

	public const int RANDOM_FASTPOLL = -300;

	public const int RANDOM_SLOWPOLL = -301;

	public const int KEYTYPE_PRIVATE = 0;

	public const int KEYTYPE_PUBLIC = 1;

	public const int KEYOPT_NONE = 0;

	public const int KEYOPT_READONLY = 1;

	public const int KEYOPT_CREATE = 2;

	public const int KEYOPT_LAST = 3;

	public const int ECCCURVE_NONE = 0;

	public const int ECCCURVE_P256 = 1;

	public const int ECCCURVE_P384 = 2;

	public const int ECCCURVE_P521 = 3;

	public const int ECCCURVE_BRAINPOOL_P256 = 4;

	public const int ECCCURVE_BRAINPOOL_P384 = 5;

	public const int ECCCURVE_BRAINPOOL_P512 = 6;

	public const int ECCCURVE_LAST = 7;

	public const int OK = 0;

	public const int ERROR_PARAM1 = -1;

	public const int ERROR_PARAM2 = -2;

	public const int ERROR_PARAM3 = -3;

	public const int ERROR_PARAM4 = -4;

	public const int ERROR_PARAM5 = -5;

	public const int ERROR_PARAM6 = -6;

	public const int ERROR_PARAM7 = -7;

	public const int ERROR_MEMORY = -10;

	public const int ERROR_NOTINITED = -11;

	public const int ERROR_INITED = -12;

	public const int ERROR_NOSECURE = -13;

	public const int ERROR_RANDOM = -14;

	public const int ERROR_FAILED = -15;

	public const int ERROR_INTERNAL = -16;

	public const int ERROR_NOTAVAIL = -20;

	public const int ERROR_PERMISSION = -21;

	public const int ERROR_WRONGKEY = -22;

	public const int ERROR_INCOMPLETE = -23;

	public const int ERROR_COMPLETE = -24;

	public const int ERROR_TIMEOUT = -25;

	public const int ERROR_INVALID = -26;

	public const int ERROR_SIGNALLED = -27;

	public const int ERROR_OVERFLOW = -30;

	public const int ERROR_UNDERFLOW = -31;

	public const int ERROR_BADDATA = -32;

	public const int ERROR_SIGNATURE = -33;

	public const int ERROR_OPEN = -40;

	public const int ERROR_READ = -41;

	public const int ERROR_WRITE = -42;

	public const int ERROR_NOTFOUND = -43;

	public const int ERROR_DUPLICATE = -44;

	public const int ENVELOPE_RESOURCE = -50;

	public static void Init()
	{
		processStatus(wrapped_Init());
	}

	public static void End()
	{
		processStatus(wrapped_End());
	}

	public static CRYPT_QUERY_INFO QueryCapability(int cryptAlgo)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_QUERY_INFO)));
		CRYPT_QUERY_INFO cRYPT_QUERY_INFO = new CRYPT_QUERY_INFO();
		try
		{
			processStatus(wrapped_QueryCapability(cryptAlgo, intPtr));
			Marshal.PtrToStructure(intPtr, (object)cRYPT_QUERY_INFO);
			return cRYPT_QUERY_INFO;
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static int CreateContext(int cryptUser, int cryptAlgo)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateContext(intPtr, cryptUser, cryptAlgo));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static void DestroyContext(int cryptContext)
	{
		processStatus(wrapped_DestroyContext(cryptContext));
	}

	public static void DestroyObject(int cryptObject)
	{
		processStatus(wrapped_DestroyObject(cryptObject));
	}

	public static void GenerateKey(int cryptContext)
	{
		processStatus(wrapped_GenerateKey(cryptContext));
	}

	public static void Encrypt(int cryptContext, byte[] buffer, int bufferOffset, int length)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(buffer, bufferOffset, length);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_Encrypt(cryptContext, bufferPtr, length));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void Encrypt(int cryptContext, byte[] buffer)
	{
		Encrypt(cryptContext, buffer, 0, buffer?.Length ?? 0);
	}

	public static void Decrypt(int cryptContext, byte[] buffer, int bufferOffset, int length)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(buffer, bufferOffset, length);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_Decrypt(cryptContext, bufferPtr, length));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void Decrypt(int cryptContext, byte[] buffer)
	{
		Decrypt(cryptContext, buffer, 0, buffer?.Length ?? 0);
	}

	public static void SetAttribute(int cryptHandle, int attributeType, int value)
	{
		processStatus(wrapped_SetAttribute(cryptHandle, attributeType, value));
	}

	public static void SetAttributeString(int cryptHandle, int attributeType, byte[] value, int valueOffset, int valueLength)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(value, valueOffset, valueLength);
			getPointer(value, valueOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_SetAttributeString(cryptHandle, attributeType, bufferPtr, valueLength));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void SetAttributeString(int cryptHandle, int attributeType, byte[] value)
	{
		SetAttributeString(cryptHandle, attributeType, value, 0, value?.Length ?? 0);
	}

	public static void SetAttributeString(int cryptHandle, int attributeType, string value)
	{
		SetAttributeString(cryptHandle, attributeType, (value == null) ? null : new UTF8Encoding().GetBytes(value), 0, (value != null) ? new UTF8Encoding().GetByteCount(value) : 0);
	}

	public static int GetAttribute(int cryptHandle, int attributeType)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_GetAttribute(cryptHandle, attributeType, intPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static int GetAttributeString(int cryptHandle, int attributeType, byte[] value, int valueOffset)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_GetAttributeString(cryptHandle, attributeType, bufferPtr, intPtr));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(value, valueOffset, sequenceLength);
			getPointer(value, valueOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_GetAttributeString(cryptHandle, attributeType, bufferPtr, intPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int GetAttributeString(int cryptHandle, int attributeType, byte[] value)
	{
		return GetAttributeString(cryptHandle, attributeType, value, 0);
	}

	public static string GetAttributeString(int cryptHandle, int attributeType)
	{
		int attributeString = GetAttributeString(cryptHandle, attributeType, null);
		byte[] array = new byte[attributeString];
		attributeString = GetAttributeString(cryptHandle, attributeType, array);
		return new UTF8Encoding().GetString(array, 0, attributeString);
	}

	public static void DeleteAttribute(int cryptHandle, int attributeType)
	{
		processStatus(wrapped_DeleteAttribute(cryptHandle, attributeType));
	}

	public static void AddRandom(byte[] randomData, int randomDataOffset, int randomDataLength)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(randomData, randomDataOffset, randomDataLength);
			getPointer(randomData, randomDataOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_AddRandom(bufferPtr, randomDataLength));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void AddRandom(byte[] randomData)
	{
		AddRandom(randomData, 0, randomData?.Length ?? 0);
	}

	public static void AddRandom(string randomData)
	{
		AddRandom((randomData == null) ? null : new UTF8Encoding().GetBytes(randomData), 0, (randomData != null) ? new UTF8Encoding().GetByteCount(randomData) : 0);
	}

	public static void AddRandom(int pollType)
	{
		processStatus(wrapped_AddRandom(IntPtr.Zero, pollType));
	}

	public static CRYPT_OBJECT_INFO QueryObject(byte[] objectData, int objectDataOffset, int objectDataLength)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_OBJECT_INFO)));
		CRYPT_OBJECT_INFO cRYPT_OBJECT_INFO = new CRYPT_OBJECT_INFO();
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(objectData, objectDataOffset, objectDataLength);
			getPointer(objectData, objectDataOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_QueryObject(bufferPtr, objectDataLength, intPtr));
			Marshal.PtrToStructure(intPtr, (object)cRYPT_OBJECT_INFO);
			return cRYPT_OBJECT_INFO;
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static CRYPT_OBJECT_INFO QueryObject(byte[] objectData)
	{
		return QueryObject(objectData, 0, objectData?.Length ?? 0);
	}

	public static CRYPT_OBJECT_INFO QueryObject(string objectData)
	{
		return QueryObject((objectData == null) ? null : new UTF8Encoding().GetBytes(objectData), 0, (objectData != null) ? new UTF8Encoding().GetByteCount(objectData) : 0);
	}

	public static int ExportKey(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyMaxLength, int exportKey, int sessionKeyContext)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_ExportKey(bufferPtr, encryptedKeyMaxLength, intPtr, exportKey, sessionKeyContext));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(encryptedKey, encryptedKeyOffset, sequenceLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_ExportKey(bufferPtr, encryptedKeyMaxLength, intPtr, exportKey, sessionKeyContext));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int ExportKey(byte[] encryptedKey, int encryptedKeyMaxLength, int exportKey, int sessionKeyContext)
	{
		return ExportKey(encryptedKey, 0, encryptedKeyMaxLength, exportKey, sessionKeyContext);
	}

	public static int ExportKeyEx(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyMaxLength, int formatType, int exportKey, int sessionKeyContext)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_ExportKeyEx(bufferPtr, encryptedKeyMaxLength, intPtr, formatType, exportKey, sessionKeyContext));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(encryptedKey, encryptedKeyOffset, sequenceLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_ExportKeyEx(bufferPtr, encryptedKeyMaxLength, intPtr, formatType, exportKey, sessionKeyContext));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int ExportKeyEx(byte[] encryptedKey, int encryptedKeyMaxLength, int formatType, int exportKey, int sessionKeyContext)
	{
		return ExportKeyEx(encryptedKey, 0, encryptedKeyMaxLength, formatType, exportKey, sessionKeyContext);
	}

	public static void ImportKey(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyLength, int importKey, int sessionKeyContext)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_ImportKey(bufferPtr, encryptedKeyLength, importKey, sessionKeyContext));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void ImportKey(byte[] encryptedKey, int importKey, int sessionKeyContext)
	{
		ImportKey(encryptedKey, 0, encryptedKey?.Length ?? 0, importKey, sessionKeyContext);
	}

	public static void ImportKey(string encryptedKey, int importKey, int sessionKeyContext)
	{
		ImportKey((encryptedKey == null) ? null : new UTF8Encoding().GetBytes(encryptedKey), 0, (encryptedKey != null) ? new UTF8Encoding().GetByteCount(encryptedKey) : 0, importKey, sessionKeyContext);
	}

	public static int ImportKeyEx(byte[] encryptedKey, int encryptedKeyOffset, int encryptedKeyLength, int importKey, int sessionKeyContext)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(encryptedKey, encryptedKeyOffset, encryptedKeyLength);
			getPointer(encryptedKey, encryptedKeyOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_ImportKeyEx(bufferPtr, encryptedKeyLength, importKey, sessionKeyContext, intPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int ImportKeyEx(byte[] encryptedKey, int importKey, int sessionKeyContext)
	{
		return ImportKeyEx(encryptedKey, 0, encryptedKey?.Length ?? 0, importKey, sessionKeyContext);
	}

	public static int ImportKeyEx(string encryptedKey, int importKey, int sessionKeyContext)
	{
		return ImportKeyEx((encryptedKey == null) ? null : new UTF8Encoding().GetBytes(encryptedKey), 0, (encryptedKey != null) ? new UTF8Encoding().GetByteCount(encryptedKey) : 0, importKey, sessionKeyContext);
	}

	public static int CreateSignature(byte[] signature, int signatureOffset, int signatureMaxLength, int signContext, int hashContext)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_CreateSignature(bufferPtr, signatureMaxLength, intPtr, signContext, hashContext));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(signature, signatureOffset, sequenceLength);
			getPointer(signature, signatureOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_CreateSignature(bufferPtr, signatureMaxLength, intPtr, signContext, hashContext));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int CreateSignature(byte[] signature, int signatureMaxLength, int signContext, int hashContext)
	{
		return CreateSignature(signature, 0, signatureMaxLength, signContext, hashContext);
	}

	public static int CreateSignatureEx(byte[] signature, int signatureOffset, int signatureMaxLength, int formatType, int signContext, int hashContext, int extraData)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_CreateSignatureEx(bufferPtr, signatureMaxLength, intPtr, formatType, signContext, hashContext, extraData));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(signature, signatureOffset, sequenceLength);
			getPointer(signature, signatureOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_CreateSignatureEx(bufferPtr, signatureMaxLength, intPtr, formatType, signContext, hashContext, extraData));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int CreateSignatureEx(byte[] signature, int signatureMaxLength, int formatType, int signContext, int hashContext, int extraData)
	{
		return CreateSignatureEx(signature, 0, signatureMaxLength, formatType, signContext, hashContext, extraData);
	}

	public static void CheckSignature(byte[] signature, int signatureOffset, int signatureLength, int sigCheckKey, int hashContext)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(signature, signatureOffset, signatureLength);
			getPointer(signature, signatureOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_CheckSignature(bufferPtr, signatureLength, sigCheckKey, hashContext));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void CheckSignature(byte[] signature, int sigCheckKey, int hashContext)
	{
		CheckSignature(signature, 0, signature?.Length ?? 0, sigCheckKey, hashContext);
	}

	public static void CheckSignature(string signature, int sigCheckKey, int hashContext)
	{
		CheckSignature((signature == null) ? null : new UTF8Encoding().GetBytes(signature), 0, (signature != null) ? new UTF8Encoding().GetByteCount(signature) : 0, sigCheckKey, hashContext);
	}

	public static int CheckSignatureEx(byte[] signature, int signatureOffset, int signatureLength, int sigCheckKey, int hashContext)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(signature, signatureOffset, signatureLength);
			getPointer(signature, signatureOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_CheckSignatureEx(bufferPtr, signatureLength, sigCheckKey, hashContext, intPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int CheckSignatureEx(byte[] signature, int sigCheckKey, int hashContext)
	{
		return CheckSignatureEx(signature, 0, signature?.Length ?? 0, sigCheckKey, hashContext);
	}

	public static int CheckSignatureEx(string signature, int sigCheckKey, int hashContext)
	{
		return CheckSignatureEx((signature == null) ? null : new UTF8Encoding().GetBytes(signature), 0, (signature != null) ? new UTF8Encoding().GetByteCount(signature) : 0, sigCheckKey, hashContext);
	}

	public static int KeysetOpen(int cryptUser, int keysetType, string name, int options)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(name);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_KeysetOpen(intPtr, cryptUser, keysetType, bufferPtr, options));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static void KeysetClose(int keyset)
	{
		processStatus(wrapped_KeysetClose(keyset));
	}

	public static int GetPublicKey(int keyset, int keyIDtype, string keyID)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_GetPublicKey(keyset, intPtr, keyIDtype, bufferPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int GetPrivateKey(int keyset, int keyIDtype, string keyID, string password)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(keyID);
		GCHandle bufferHandle2 = default;
		IntPtr bufferPtr2 = IntPtr.Zero;
		byte[] bytes2 = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			getPointer(bytes2, 0, ref bufferHandle2, ref bufferPtr2);
			processStatus(wrapped_GetPrivateKey(keyset, intPtr, keyIDtype, bufferPtr, bufferPtr2));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
			releasePointer(bufferHandle2);
		}
	}

	public static int GetKey(int keyset, int keyIDtype, string keyID, string password)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(keyID);
		GCHandle bufferHandle2 = default;
		IntPtr bufferPtr2 = IntPtr.Zero;
		byte[] bytes2 = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			getPointer(bytes2, 0, ref bufferHandle2, ref bufferPtr2);
			processStatus(wrapped_GetKey(keyset, intPtr, keyIDtype, bufferPtr, bufferPtr2));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
			releasePointer(bufferHandle2);
		}
	}

	public static void AddPublicKey(int keyset, int certificate)
	{
		processStatus(wrapped_AddPublicKey(keyset, certificate));
	}

	public static void AddPrivateKey(int keyset, int cryptKey, string password)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_AddPrivateKey(keyset, cryptKey, bufferPtr));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void DeleteKey(int keyset, int keyIDtype, string keyID)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_DeleteKey(keyset, keyIDtype, bufferPtr));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static int CreateCert(int cryptUser, int certType)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateCert(intPtr, cryptUser, certType));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static void DestroyCert(int certificate)
	{
		processStatus(wrapped_DestroyCert(certificate));
	}

	public static int GetCertExtension(int certificate, string oid, byte[] extension, int extensionOffset, int extensionMaxLength)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		IntPtr criticalFlag = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(oid);
		GCHandle bufferHandle2 = default;
		IntPtr bufferPtr2 = IntPtr.Zero;
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_GetCertExtension(certificate, bufferPtr, criticalFlag, bufferPtr2, extensionMaxLength, intPtr));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(extension, extensionOffset, sequenceLength);
			getPointer(extension, extensionOffset, ref bufferHandle2, ref bufferPtr2);
			processStatus(wrapped_GetCertExtension(certificate, bufferPtr, criticalFlag, bufferPtr2, extensionMaxLength, intPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle2);
			releasePointer(bufferHandle);
		}
	}

	public static int GetCertExtension(int certificate, string oid, byte[] extension, int extensionMaxLength)
	{
		return GetCertExtension(certificate, oid, extension, 0, extensionMaxLength);
	}

	public static void AddCertExtension(int certificate, string oid, int criticalFlag, byte[] extension, int extensionOffset, int extensionLength)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(oid);
		GCHandle bufferHandle2 = default;
		IntPtr bufferPtr2 = IntPtr.Zero;
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			checkIndices(extension, extensionOffset, extensionLength);
			getPointer(extension, extensionOffset, ref bufferHandle2, ref bufferPtr2);
			processStatus(wrapped_AddCertExtension(certificate, bufferPtr, criticalFlag, bufferPtr2, extensionLength));
		}
		finally
		{
			releasePointer(bufferHandle2);
			releasePointer(bufferHandle);
		}
	}

	public static void AddCertExtension(int certificate, string oid, int criticalFlag, byte[] extension)
	{
		AddCertExtension(certificate, oid, criticalFlag, extension, 0, extension?.Length ?? 0);
	}

	public static void AddCertExtension(int certificate, string oid, int criticalFlag, string extension)
	{
		AddCertExtension(certificate, oid, criticalFlag, (extension == null) ? null : new UTF8Encoding().GetBytes(extension), 0, (extension != null) ? new UTF8Encoding().GetByteCount(extension) : 0);
	}

	public static void DeleteCertExtension(int certificate, string oid)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(oid);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_DeleteCertExtension(certificate, bufferPtr));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static void SignCert(int certificate, int signContext)
	{
		processStatus(wrapped_SignCert(certificate, signContext));
	}

	public static void CheckCert(int certificate, int sigCheckKey)
	{
		processStatus(wrapped_CheckCert(certificate, sigCheckKey));
	}

	public static int ImportCert(byte[] certObject, int certObjectOffset, int certObjectLength, int cryptUser)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			checkIndices(certObject, certObjectOffset, certObjectLength);
			getPointer(certObject, certObjectOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_ImportCert(bufferPtr, certObjectLength, cryptUser, intPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int ImportCert(byte[] certObject, int cryptUser)
	{
		return ImportCert(certObject, 0, certObject?.Length ?? 0, cryptUser);
	}

	public static int ImportCert(string certObject, int cryptUser)
	{
		return ImportCert((certObject == null) ? null : new UTF8Encoding().GetBytes(certObject), 0, (certObject != null) ? new UTF8Encoding().GetByteCount(certObject) : 0, cryptUser);
	}

	public static int ExportCert(byte[] certObject, int certObjectOffset, int certObjectMaxLength, int certFormatType, int certificate)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			processStatus(wrapped_ExportCert(bufferPtr, certObjectMaxLength, intPtr, certFormatType, certificate));
			int sequenceLength = Marshal.ReadInt32(intPtr);
			checkIndices(certObject, certObjectOffset, sequenceLength);
			getPointer(certObject, certObjectOffset, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_ExportCert(bufferPtr, certObjectMaxLength, intPtr, certFormatType, certificate));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int ExportCert(byte[] certObject, int certObjectMaxLength, int certFormatType, int certificate)
	{
		return ExportCert(certObject, 0, certObjectMaxLength, certFormatType, certificate);
	}

	public static void CAAddItem(int keyset, int certificate)
	{
		processStatus(wrapped_CAAddItem(keyset, certificate));
	}

	public static int CAGetItem(int keyset, int certType, int keyIDtype, string keyID)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_CAGetItem(keyset, intPtr, certType, keyIDtype, bufferPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static void CADeleteItem(int keyset, int certType, int keyIDtype, string keyID)
	{
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(keyID);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_CADeleteItem(keyset, certType, keyIDtype, bufferPtr));
		}
		finally
		{
			releasePointer(bufferHandle);
		}
	}

	public static int CACertManagement(int action, int keyset, int caKey, int certRequest)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CACertManagement(intPtr, action, keyset, caKey, certRequest));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static int CreateEnvelope(int cryptUser, int formatType)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateEnvelope(intPtr, cryptUser, formatType));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static void DestroyEnvelope(int envelope)
	{
		processStatus(wrapped_DestroyEnvelope(envelope));
	}

	public static int CreateSession(int cryptUser, int formatType)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_CreateSession(intPtr, cryptUser, formatType));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static void DestroySession(int session)
	{
		processStatus(wrapped_DestroySession(session));
	}

	public static int PushData(int envelope, byte[] buffer, int bufferOffset, int length)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			int num = 0;
			checkIndices(buffer, bufferOffset, length);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			int status = wrapped_PushData(envelope, bufferPtr, length, intPtr);
			num = Marshal.ReadInt32(intPtr);
			processStatus(status, num);
			return num;
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int PushData(int envelope, byte[] buffer)
	{
		return PushData(envelope, buffer, 0, buffer?.Length ?? 0);
	}

	public static int PushData(int envelope, string buffer)
	{
		return PushData(envelope, (buffer == null) ? null : new UTF8Encoding().GetBytes(buffer), 0, (buffer != null) ? new UTF8Encoding().GetByteCount(buffer) : 0);
	}

	public static void FlushData(int envelope)
	{
		processStatus(wrapped_FlushData(envelope));
	}

	public static int PopData(int envelope, byte[] buffer, int bufferOffset, int length)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		try
		{
			int sequenceLength = 0;
			checkIndices(buffer, bufferOffset, sequenceLength);
			getPointer(buffer, bufferOffset, ref bufferHandle, ref bufferPtr);
			int status = wrapped_PopData(envelope, bufferPtr, length, intPtr);
			sequenceLength = Marshal.ReadInt32(intPtr);
			processStatus(status, sequenceLength);
			return sequenceLength;
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static int PopData(int envelope, byte[] buffer, int length)
	{
		return PopData(envelope, buffer, 0, length);
	}

	public static int DeviceOpen(int cryptUser, int deviceType, string name)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(name);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			processStatus(wrapped_DeviceOpen(intPtr, cryptUser, deviceType, bufferPtr));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
		}
	}

	public static void DeviceClose(int device)
	{
		processStatus(wrapped_DeviceClose(device));
	}

	public static CRYPT_QUERY_INFO DeviceQueryCapability(int device, int cryptAlgo)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPT_QUERY_INFO)));
		CRYPT_QUERY_INFO cRYPT_QUERY_INFO = new CRYPT_QUERY_INFO();
		try
		{
			processStatus(wrapped_DeviceQueryCapability(device, cryptAlgo, intPtr));
			Marshal.PtrToStructure(intPtr, (object)cRYPT_QUERY_INFO);
			return cRYPT_QUERY_INFO;
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static int DeviceCreateContext(int device, int cryptAlgo)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		try
		{
			processStatus(wrapped_DeviceCreateContext(device, intPtr, cryptAlgo));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
		}
	}

	public static int Login(string name, string password)
	{
		IntPtr intPtr = Marshal.AllocHGlobal(4);
		GCHandle bufferHandle = default;
		IntPtr bufferPtr = IntPtr.Zero;
		byte[] bytes = new UTF8Encoding().GetBytes(name);
		GCHandle bufferHandle2 = default;
		IntPtr bufferPtr2 = IntPtr.Zero;
		byte[] bytes2 = new UTF8Encoding().GetBytes(password);
		try
		{
			getPointer(bytes, 0, ref bufferHandle, ref bufferPtr);
			getPointer(bytes2, 0, ref bufferHandle2, ref bufferPtr2);
			processStatus(wrapped_Login(intPtr, bufferPtr, bufferPtr2));
			return Marshal.ReadInt32(intPtr);
		}
		finally
		{
			Marshal.FreeHGlobal(intPtr);
			releasePointer(bufferHandle);
			releasePointer(bufferHandle2);
		}
	}

	public static void Logout(int user)
	{
		processStatus(wrapped_Logout(user));
	}

	[DllImport("cl32.dll", EntryPoint = "cryptInit")]
	private static extern int wrapped_Init();

	[DllImport("cl32.dll", EntryPoint = "cryptEnd")]
	private static extern int wrapped_End();

	[DllImport("cl32.dll", EntryPoint = "cryptQueryCapability")]
	private static extern int wrapped_QueryCapability(int cryptAlgo, IntPtr cryptQueryInfo);

	[DllImport("cl32.dll", EntryPoint = "cryptCreateContext")]
	private static extern int wrapped_CreateContext(IntPtr cryptContext, int cryptUser, int cryptAlgo);

	[DllImport("cl32.dll", EntryPoint = "cryptDestroyContext")]
	private static extern int wrapped_DestroyContext(int cryptContext);

	[DllImport("cl32.dll", EntryPoint = "cryptDestroyObject")]
	private static extern int wrapped_DestroyObject(int cryptObject);

	[DllImport("cl32.dll", EntryPoint = "cryptGenerateKey")]
	private static extern int wrapped_GenerateKey(int cryptContext);

	[DllImport("cl32.dll", EntryPoint = "cryptEncrypt")]
	private static extern int wrapped_Encrypt(int cryptContext, IntPtr buffer, int length);

	[DllImport("cl32.dll", EntryPoint = "cryptDecrypt")]
	private static extern int wrapped_Decrypt(int cryptContext, IntPtr buffer, int length);

	[DllImport("cl32.dll", EntryPoint = "cryptSetAttribute")]
	private static extern int wrapped_SetAttribute(int cryptHandle, int attributeType, int value);

	[DllImport("cl32.dll", EntryPoint = "cryptSetAttributeString")]
	private static extern int wrapped_SetAttributeString(int cryptHandle, int attributeType, IntPtr value, int valueLength);

	[DllImport("cl32.dll", EntryPoint = "cryptGetAttribute")]
	private static extern int wrapped_GetAttribute(int cryptHandle, int attributeType, IntPtr value);

	[DllImport("cl32.dll", EntryPoint = "cryptGetAttributeString")]
	private static extern int wrapped_GetAttributeString(int cryptHandle, int attributeType, IntPtr value, IntPtr valueLength);

	[DllImport("cl32.dll", EntryPoint = "cryptDeleteAttribute")]
	private static extern int wrapped_DeleteAttribute(int cryptHandle, int attributeType);

	[DllImport("cl32.dll", EntryPoint = "cryptAddRandom")]
	private static extern int wrapped_AddRandom(IntPtr randomData, int randomDataLength);

	[DllImport("cl32.dll", EntryPoint = "cryptQueryObject")]
	private static extern int wrapped_QueryObject(IntPtr objectData, int objectDataLength, IntPtr cryptObjectInfo);

	[DllImport("cl32.dll", EntryPoint = "cryptExportKey")]
	private static extern int wrapped_ExportKey(IntPtr encryptedKey, int encryptedKeyMaxLength, IntPtr encryptedKeyLength, int exportKey, int sessionKeyContext);

	[DllImport("cl32.dll", EntryPoint = "cryptExportKeyEx")]
	private static extern int wrapped_ExportKeyEx(IntPtr encryptedKey, int encryptedKeyMaxLength, IntPtr encryptedKeyLength, int formatType, int exportKey, int sessionKeyContext);

	[DllImport("cl32.dll", EntryPoint = "cryptImportKey")]
	private static extern int wrapped_ImportKey(IntPtr encryptedKey, int encryptedKeyLength, int importKey, int sessionKeyContext);

	[DllImport("cl32.dll", EntryPoint = "cryptImportKeyEx")]
	private static extern int wrapped_ImportKeyEx(IntPtr encryptedKey, int encryptedKeyLength, int importKey, int sessionKeyContext, IntPtr returnedContext);

	[DllImport("cl32.dll", EntryPoint = "cryptCreateSignature")]
	private static extern int wrapped_CreateSignature(IntPtr signature, int signatureMaxLength, IntPtr signatureLength, int signContext, int hashContext);

	[DllImport("cl32.dll", EntryPoint = "cryptCreateSignatureEx")]
	private static extern int wrapped_CreateSignatureEx(IntPtr signature, int signatureMaxLength, IntPtr signatureLength, int formatType, int signContext, int hashContext, int extraData);

	[DllImport("cl32.dll", EntryPoint = "cryptCheckSignature")]
	private static extern int wrapped_CheckSignature(IntPtr signature, int signatureLength, int sigCheckKey, int hashContext);

	[DllImport("cl32.dll", EntryPoint = "cryptCheckSignatureEx")]
	private static extern int wrapped_CheckSignatureEx(IntPtr signature, int signatureLength, int sigCheckKey, int hashContext, IntPtr extraData);

	[DllImport("cl32.dll", EntryPoint = "cryptKeysetOpen")]
	private static extern int wrapped_KeysetOpen(IntPtr keyset, int cryptUser, int keysetType, IntPtr name, int options);

	[DllImport("cl32.dll", EntryPoint = "cryptKeysetClose")]
	private static extern int wrapped_KeysetClose(int keyset);

	[DllImport("cl32.dll", EntryPoint = "cryptGetPublicKey")]
	private static extern int wrapped_GetPublicKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint = "cryptGetPrivateKey")]
	private static extern int wrapped_GetPrivateKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID, IntPtr password);

	[DllImport("cl32.dll", EntryPoint = "cryptGetKey")]
	private static extern int wrapped_GetKey(int keyset, IntPtr cryptContext, int keyIDtype, IntPtr keyID, IntPtr password);

	[DllImport("cl32.dll", EntryPoint = "cryptAddPublicKey")]
	private static extern int wrapped_AddPublicKey(int keyset, int certificate);

	[DllImport("cl32.dll", EntryPoint = "cryptAddPrivateKey")]
	private static extern int wrapped_AddPrivateKey(int keyset, int cryptKey, IntPtr password);

	[DllImport("cl32.dll", EntryPoint = "cryptDeleteKey")]
	private static extern int wrapped_DeleteKey(int keyset, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint = "cryptCreateCert")]
	private static extern int wrapped_CreateCert(IntPtr certificate, int cryptUser, int certType);

	[DllImport("cl32.dll", EntryPoint = "cryptDestroyCert")]
	private static extern int wrapped_DestroyCert(int certificate);

	[DllImport("cl32.dll", EntryPoint = "cryptGetCertExtension")]
	private static extern int wrapped_GetCertExtension(int certificate, IntPtr oid, IntPtr criticalFlag, IntPtr extension, int extensionMaxLength, IntPtr extensionLength);

	[DllImport("cl32.dll", EntryPoint = "cryptAddCertExtension")]
	private static extern int wrapped_AddCertExtension(int certificate, IntPtr oid, int criticalFlag, IntPtr extension, int extensionLength);

	[DllImport("cl32.dll", EntryPoint = "cryptDeleteCertExtension")]
	private static extern int wrapped_DeleteCertExtension(int certificate, IntPtr oid);

	[DllImport("cl32.dll", EntryPoint = "cryptSignCert")]
	private static extern int wrapped_SignCert(int certificate, int signContext);

	[DllImport("cl32.dll", EntryPoint = "cryptCheckCert")]
	private static extern int wrapped_CheckCert(int certificate, int sigCheckKey);

	[DllImport("cl32.dll", EntryPoint = "cryptImportCert")]
	private static extern int wrapped_ImportCert(IntPtr certObject, int certObjectLength, int cryptUser, IntPtr certificate);

	[DllImport("cl32.dll", EntryPoint = "cryptExportCert")]
	private static extern int wrapped_ExportCert(IntPtr certObject, int certObjectMaxLength, IntPtr certObjectLength, int certFormatType, int certificate);

	[DllImport("cl32.dll", EntryPoint = "cryptCAAddItem")]
	private static extern int wrapped_CAAddItem(int keyset, int certificate);

	[DllImport("cl32.dll", EntryPoint = "cryptCAGetItem")]
	private static extern int wrapped_CAGetItem(int keyset, IntPtr certificate, int certType, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint = "cryptCADeleteItem")]
	private static extern int wrapped_CADeleteItem(int keyset, int certType, int keyIDtype, IntPtr keyID);

	[DllImport("cl32.dll", EntryPoint = "cryptCACertManagement")]
	private static extern int wrapped_CACertManagement(IntPtr certificate, int action, int keyset, int caKey, int certRequest);

	[DllImport("cl32.dll", EntryPoint = "cryptCreateEnvelope")]
	private static extern int wrapped_CreateEnvelope(IntPtr envelope, int cryptUser, int formatType);

	[DllImport("cl32.dll", EntryPoint = "cryptDestroyEnvelope")]
	private static extern int wrapped_DestroyEnvelope(int envelope);

	[DllImport("cl32.dll", EntryPoint = "cryptCreateSession")]
	private static extern int wrapped_CreateSession(IntPtr session, int cryptUser, int formatType);

	[DllImport("cl32.dll", EntryPoint = "cryptDestroySession")]
	private static extern int wrapped_DestroySession(int session);

	[DllImport("cl32.dll", EntryPoint = "cryptPushData")]
	private static extern int wrapped_PushData(int envelope, IntPtr buffer, int length, IntPtr bytesCopied);

	[DllImport("cl32.dll", EntryPoint = "cryptFlushData")]
	private static extern int wrapped_FlushData(int envelope);

	[DllImport("cl32.dll", EntryPoint = "cryptPopData")]
	private static extern int wrapped_PopData(int envelope, IntPtr buffer, int length, IntPtr bytesCopied);

	[DllImport("cl32.dll", EntryPoint = "cryptDeviceOpen")]
	private static extern int wrapped_DeviceOpen(IntPtr device, int cryptUser, int deviceType, IntPtr name);

	[DllImport("cl32.dll", EntryPoint = "cryptDeviceClose")]
	private static extern int wrapped_DeviceClose(int device);

	[DllImport("cl32.dll", EntryPoint = "cryptDeviceQueryCapability")]
	private static extern int wrapped_DeviceQueryCapability(int device, int cryptAlgo, IntPtr cryptQueryInfo);

	[DllImport("cl32.dll", EntryPoint = "cryptDeviceCreateContext")]
	private static extern int wrapped_DeviceCreateContext(int device, IntPtr cryptContext, int cryptAlgo);

	[DllImport("cl32.dll", EntryPoint = "cryptLogin")]
	private static extern int wrapped_Login(IntPtr user, IntPtr name, IntPtr password);

	[DllImport("cl32.dll", EntryPoint = "cryptLogout")]
	private static extern int wrapped_Logout(int user);

	private static void processStatus(int status)
	{
		if (status < 0)
		{
			throw new CryptException(status);
		}
	}

	private static void processStatus(int status, int extraInfo)
	{
		if (status < 0)
		{
			throw new CryptException(status, extraInfo);
		}
	}

	private static void checkIndices(byte[] array, int sequenceOffset, int sequenceLength)
	{
		if (array == null)
		{
			if (sequenceOffset != 0)
			{
				throw new IndexOutOfRangeException();
			}
			return;
		}
		int num = array.Length;
		if (sequenceOffset < 0 || sequenceOffset >= num || sequenceOffset + sequenceLength > num)
		{
			throw new IndexOutOfRangeException();
		}
	}

	private static void getPointer(byte[] buffer, int bufferOffset, ref GCHandle bufferHandle, ref IntPtr bufferPtr)
	{
		if (buffer != null)
		{
			bufferHandle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
			bufferPtr = Marshal.UnsafeAddrOfPinnedArrayElement((Array)buffer, bufferOffset);
		}
	}

	private static void releasePointer(GCHandle bufferHandle)
	{
		if (bufferHandle.IsAllocated)
		{
			bufferHandle.Free();
		}
	}
}

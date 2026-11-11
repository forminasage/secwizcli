using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using cryptlib;

namespace NMCSecurityWizardCLI;

internal class Program
{
	private static Logger myLogger;

	private static void Main(string[] args)
	{
		myLogger = new Logger("result.log", "error.log");
		ArgsParser argsParser = new ArgsParser(args);
		Globals._ParseError parseError = Globals._ParseError.ParseErrorNone;
		DisplaySplashHeader();
		switch (parseError = argsParser.ProcessCommandLineArgs())
		{
		case Globals._ParseError.ParseFunctionArgsIncomplete:
			if (args.Length > 0)
			{
				myLogger.AddEvent(Globals._LogStorage.LogError, "One or more arguments are missing. Please verify and retry.");
			}
			break;
		case Globals._ParseError.ParseErrorUnknownArgument:
			myLogger.AddEvent(Globals._LogStorage.LogError, "One or more arguments entered is unknown. Please verify and retry.");
			break;
		case Globals._ParseError.ParseErrorTimestampFormat:
			myLogger.AddEvent(Globals._LogStorage.LogError, "{0} parameter has been entered incorrectly. Please verify and retry.", "Timestamp");
			break;
		case Globals._ParseError.ParseErrorKeySize:
			myLogger.AddEvent(Globals._LogStorage.LogError, "{0} parameter has been entered incorrectly. Please verify and retry.", "Key size");
			break;
		case Globals._ParseError.ParseErrorEmailAddress:
			myLogger.AddEvent(Globals._LogStorage.LogError, "{0} parameter has been entered incorrectly. Please verify and retry.", "E-mail");
			break;
		case Globals._ParseError.ParseErrorDNSName:
			myLogger.AddEvent(Globals._LogStorage.LogError, "{0} parameter has been entered incorrectly. Please verify and retry.", "DNS name (7 characters minimum)");
			break;
		case Globals._ParseError.ParseErrorCountryCode:
			myLogger.AddEvent(Globals._LogStorage.LogError, "{0} parameter has been entered incorrectly. Please verify and retry.", "Country");
			break;
		case Globals._ParseError.ParseErrorInvalidFileName:
			myLogger.AddEvent(Globals._LogStorage.LogError, "Filename '{0}' does not meet the supported naming convention. Please verify and retry.", argsParser.outputFile);
			break;
		case Globals._ParseError.ParseErrorKeyDoesNotExist:
			myLogger.AddEvent(Globals._LogStorage.LogError, "Input file '{0}.p15' does not exist. Please verify and retry.", argsParser.privKeyIn);
			break;
		case Globals._ParseError.ParseErrorCARootDoesNotExist:
			myLogger.AddEvent(Globals._LogStorage.LogError, "Input file '{0}.p15' does not exist. Please verify and retry.", argsParser.caRootCertIn);
			break;
		case Globals._ParseError.ParseErrorSignedCertDoesNotExist:
			myLogger.AddEvent(Globals._LogStorage.LogError, "Input file '{0}.p15' does not exist. Please verify and retry.", argsParser.signedCertIn);
			break;
		case Globals._ParseError.ParseErrorTimestampRange:
			myLogger.AddEvent(Globals._LogStorage.LogError, "Validity 'From' and 'To' dates are not in range. Please verify and retry.");
			break;
		}
		if (parseError != Globals._ParseError.ParseErrorNone)
		{
			Console.WriteLine("");
			DisplayCommandLineSyntax();
			Environment.Exit(1);
		}
		if (!File.Exists("cl32.dll"))
		{
			Console.WriteLine("* cl32.dll is not in the current directory; exiting...");
			Environment.Exit(1);
		}
		crypt.Init();
		crypt.SetAttribute(crypt.UNUSED, crypt.OPTION_ENCR_HASH, crypt.ALGO_SHA2);
		crypt.SetAttribute(crypt.UNUSED, crypt.OPTION_ENCR_ALGO, crypt.ALGO_3DES);
		crypt.SetAttribute(crypt.UNUSED, crypt.OPTION_CERT_COMPLIANCELEVEL, crypt.COMPLIANCELEVEL_REDUCED);
		crypt.SetAttribute(crypt.UNUSED, crypt.OPTION_KEYING_ITERATIONS, 5000);
		switch (argsParser.functionType)
		{
		case Globals._FunctionType.CreateSSLCert:
		{
			Certificate cCertIn = new Certificate(argsParser.outputFile, Convert.ToInt32(argsParser.keySize), argsParser.commonNameDN, argsParser.countryDN, argsParser.stateProvinceDN, argsParser.localityDN, argsParser.organizationDN, argsParser.organizationalUnitDN, argsParser.validityFromDN, argsParser.validityToDN, argsParser.emailAddressSAN, argsParser.uriNameSAN, argsParser.dnsNameSAN, argsParser.ipAddressSAN);
			if (CreateSSLCert(cCertIn, argsParser.caRootCertIn))
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "SSL certificate '{0}' has been successfully created.", argsParser.outputFile);
			}
			else
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "SSL certificate '{0}' could not be generated; recheck settings.", argsParser.outputFile);
			}
			break;
		}
		case Globals._FunctionType.CreateSSHKey:
			if (CreateSSHServerHostKey(argsParser.outputFile, argsParser.keySize))
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "SSH host key '{0}' has been successfully created.", argsParser.outputFile);
			}
			else
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "SSH host key '{0}' could not be generated; recheck settings.", argsParser.outputFile);
			}
			break;
		case Globals._FunctionType.CreateCARootCert:
		{
			Certificate cCertIn2 = new Certificate(argsParser.outputFile, Convert.ToInt32(argsParser.keySize), argsParser.commonNameDN, argsParser.countryDN, argsParser.stateProvinceDN, argsParser.localityDN, argsParser.organizationDN, argsParser.organizationalUnitDN, argsParser.validityFromDN, argsParser.validityToDN, argsParser.emailAddressSAN, argsParser.uriNameSAN, argsParser.dnsNameSAN, argsParser.ipAddressSAN);
			if (CreateCARootCert(cCertIn2))
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "CA root cert and private key '{0}' have been successfully created.", argsParser.outputFile);
			}
			else
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "CA root cert and private key '{0}' could not be generated; recheck settings.", argsParser.outputFile);
			}
			break;
		}
		case Globals._FunctionType.CreateCSR:
		{
			Certificate cCertIn3 = new Certificate(argsParser.outputFile, Convert.ToInt32(argsParser.keySize), argsParser.commonNameDN, argsParser.countryDN, argsParser.stateProvinceDN, argsParser.localityDN, argsParser.organizationDN, argsParser.organizationalUnitDN, argsParser.validityFromDN, argsParser.validityToDN, argsParser.emailAddressSAN, argsParser.uriNameSAN, argsParser.dnsNameSAN, argsParser.ipAddressSAN);
			if (GenerateCSR(cCertIn3))
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "CSR and private key '{0}' have been successfully created.", argsParser.outputFile);
			}
			else
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "CSR and private key '{0}' could not be generated; recheck settings.", argsParser.outputFile);
			}
			break;
		}
		case Globals._FunctionType.ImportCert:
			if (ImportSignedCSR(argsParser.signedCertIn, argsParser.privKeyIn, argsParser.outputFile))
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "Importing certificate '{0}' has successfully completed.", argsParser.outputFile);
			}
			else
			{
				myLogger.AddEvent(Globals._LogStorage.LogResult, "Importing certificate '{0}' could not be completed; recheck settings.", argsParser.outputFile);
			}
			break;
		default:
			DisplayCommandLineSyntax();
			break;
		}
		crypt.End();
		Environment.Exit(0);
	}

	private static bool CreateSSLCert(Certificate cCertIn, string sCaRootCertIn)
	{
		int num = crypt.CreateContext(crypt.UNUSED, crypt.ALGO_RSA);
		crypt.SetAttribute(num, crypt.CTXINFO_KEYSIZE, cCertIn.GetKeySize() / 8);
		crypt.SetAttributeString(num, crypt.CTXINFO_LABEL, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, cCertIn.GetFileName() + ".p15", crypt.KEYOPT_CREATE);
		crypt.AddPrivateKey(keyset, num, "user");
		int num2 = crypt.CreateCert(crypt.UNUSED, crypt.CERTTYPE_CERTREQUEST);
		crypt.SetAttribute(num2, crypt.CERTINFO_SUBJECTPUBLICKEYINFO, num);
		SetDNAttributes(num2, cCertIn, bUseValidity: false);
		SetSANAttributes(num2, cCertIn);
		crypt.SignCert(num2, num);
		int keyset2;
		try
		{
			keyset2 = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, sCaRootCertIn + ".p15", crypt.KEYOPT_READONLY);
		}
		catch (CryptException)
		{
			crypt.KeysetClose(keyset);
			crypt.DestroyContext(num);
			crypt.DestroyCert(num2);
			File.Delete(cCertIn.GetFileName() + ".p15");
			return false;
		}
		int privateKey = crypt.GetPrivateKey(keyset2, crypt.KEYID_NAME, "Private key", "root");
		crypt.KeysetClose(keyset2);
		int num3 = crypt.CreateCert(crypt.UNUSED, crypt.CERTTYPE_CERTIFICATE);
		crypt.SetAttribute(num3, crypt.CERTINFO_CERTREQUEST, num2);
		if (cCertIn.GetValidityPeriodStart() != 0 && cCertIn.GetValidityPeriodEnd() != 0)
		{
			crypt.SetAttributeString(num3, crypt.CERTINFO_VALIDFROM, BitConverter.GetBytes(cCertIn.GetValidityPeriodStart()));
			crypt.SetAttributeString(num3, crypt.CERTINFO_VALIDTO, BitConverter.GetBytes(cCertIn.GetValidityPeriodEnd()));
		}
		crypt.SignCert(num3, privateKey);
		crypt.AddPublicKey(keyset, num3);
		int num4 = crypt.ExportCert(null, 0, crypt.CERTFORMAT_CERTIFICATE, num3);
		byte[] array = new byte[num4];
		crypt.ExportCert(array, array.Length, crypt.CERTFORMAT_CERTIFICATE, num3);
		DisplayCertificateSummary(num3);
		File.WriteAllBytes(cCertIn.GetFileName() + ".crt", array);
		crypt.KeysetClose(keyset);
		crypt.DestroyContext(num);
		crypt.DestroyContext(privateKey);
		crypt.DestroyCert(num2);
		crypt.DestroyCert(num3);
		AttachAPCFileHeader(cCertIn.GetFileName() + ".p15", Globals._FlashFileFileType.SSLServerCert);
		return true;
	}

	private static bool GenerateCSR(Certificate cCertIn)
	{
		int num = crypt.CreateContext(crypt.UNUSED, crypt.ALGO_RSA);
		crypt.SetAttribute(num, crypt.CTXINFO_KEYSIZE, cCertIn.GetKeySize() / 8);
		crypt.SetAttributeString(num, crypt.CTXINFO_LABEL, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, cCertIn.GetFileName() + ".p15", crypt.KEYOPT_CREATE);
		crypt.AddPrivateKey(keyset, num, "user");
		crypt.KeysetClose(keyset);
		int num2 = crypt.CreateCert(crypt.UNUSED, crypt.CERTTYPE_CERTREQUEST);
		crypt.SetAttribute(num2, crypt.CERTINFO_SUBJECTPUBLICKEYINFO, num);
		SetDNAttributes(num2, cCertIn, bUseValidity: false);
		SetSANAttributes(num2, cCertIn);
		crypt.SignCert(num2, num);
		crypt.DestroyContext(num);
		int num3 = crypt.ExportCert(null, 0, crypt.CERTFORMAT_TEXT_CERTIFICATE, num2);
		byte[] array = new byte[num3 + 1];
		crypt.ExportCert(array, array.Length, crypt.CERTFORMAT_TEXT_CERTIFICATE, num2);
		crypt.DestroyCert(num2);
		File.WriteAllBytes(cCertIn.GetFileName() + ".csr", array);
		return true;
	}

	private static bool CreateSSHServerHostKey(string sOutFile, int sKeySize)
	{
		int num = crypt.CreateContext(crypt.UNUSED, crypt.ALGO_RSA);
		crypt.SetAttribute(num, crypt.CTXINFO_KEYSIZE, sKeySize / 8);
		crypt.SetAttributeString(num, crypt.CTXINFO_LABEL, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, sOutFile + ".p15", crypt.KEYOPT_CREATE);
		crypt.AddPrivateKey(keyset, num, "user");
		crypt.KeysetClose(keyset);
		crypt.DestroyContext(num);
		AttachAPCFileHeader(sOutFile + ".p15", Globals._FlashFileFileType.SSHKey);
		return true;
	}

	private static bool CreateCARootCert(Certificate cCertIn)
	{
		int num = crypt.CreateContext(crypt.UNUSED, crypt.ALGO_RSA);
		crypt.SetAttribute(num, crypt.CTXINFO_KEYSIZE, cCertIn.GetKeySize() / 8);
		crypt.SetAttributeString(num, crypt.CTXINFO_LABEL, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, cCertIn.GetFileName() + ".p15", crypt.KEYOPT_CREATE);
		crypt.AddPrivateKey(keyset, num, "root");
		crypt.KeysetClose(keyset);
		int num2 = crypt.CreateCert(crypt.UNUSED, crypt.CERTTYPE_CERTIFICATE);
		crypt.SetAttribute(num2, crypt.CERTINFO_SUBJECTPUBLICKEYINFO, num);
		SetDNAttributes(num2, cCertIn, bUseValidity: true);
		SetSANAttributes(num2, cCertIn);
		crypt.SetAttribute(num2, crypt.CERTINFO_SELFSIGNED, 1);
		crypt.SetAttribute(num2, crypt.CERTINFO_KEYUSAGE, crypt.KEYUSAGE_KEYCERTSIGN | crypt.KEYUSAGE_CRLSIGN);
		crypt.SetAttribute(num2, crypt.CERTINFO_CA, 1);
		crypt.SignCert(num2, num);
		crypt.DestroyContext(num);
		keyset = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, cCertIn.GetFileName() + ".p15", crypt.KEYOPT_NONE);
		crypt.AddPublicKey(keyset, num2);
		crypt.KeysetClose(keyset);
		int num3 = crypt.ExportCert(null, 0, crypt.CERTFORMAT_CERTIFICATE, num2);
		byte[] array = new byte[num3];
		crypt.ExportCert(array, array.Length, crypt.CERTFORMAT_CERTIFICATE, num2);
		File.WriteAllBytes(cCertIn.GetFileName() + ".crt", array);
		DisplayCertificateSummary(num2);
		crypt.DestroyCert(num2);
		return true;
	}

	private static bool ImportSignedCSR(string sCertFile, string sKeyFile, string sOutFile)
	{
		File.WriteAllBytes(sOutFile + ".p15", File.ReadAllBytes(sKeyFile + ".p15"));
		byte[] certObject = File.ReadAllBytes(sCertFile);
		int num = crypt.ImportCert(certObject, crypt.UNUSED);
		int keyset = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, sOutFile + ".p15", crypt.KEYOPT_NONE);
		crypt.AddPublicKey(keyset, num);
		crypt.KeysetClose(keyset);
		DisplayCertificateSummary(num);
		crypt.DestroyCert(num);
		AttachAPCFileHeader(sOutFile + ".p15", Globals._FlashFileFileType.SSLServerCert);
		return true;
	}

	private static void SetDNAttributes(int certRequest, Certificate cCert, bool bUseValidity)
	{
		crypt.SetAttributeString(certRequest, crypt.CERTINFO_COMMONNAME, cCert.GetCommonName());
		crypt.SetAttributeString(certRequest, crypt.CERTINFO_COUNTRYNAME, cCert.GetCountry());
		if (cCert.GetStateOrProvince() != null)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_STATEORPROVINCENAME, cCert.GetStateOrProvince());
		}
		if (cCert.GetLocality() != null)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_LOCALITYNAME, cCert.GetLocality());
		}
		if (cCert.GetOrganization() != null)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_ORGANIZATIONNAME, cCert.GetOrganization());
		}
		if (cCert.GetOrganizationalUnit() != null)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_ORGANIZATIONALUNITNAME, cCert.GetOrganizationalUnit());
		}
		if (bUseValidity && cCert.GetValidityPeriodStart() != 0 && cCert.GetValidityPeriodEnd() != 0)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_VALIDFROM, BitConverter.GetBytes(cCert.GetValidityPeriodStart()));
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_VALIDTO, BitConverter.GetBytes(cCert.GetValidityPeriodEnd()));
		}
	}

	private static void SetSANAttributes(int certRequest, Certificate cCert)
	{
		// GeneralName fields default to subjectAltName. Selecting it explicitly makes
		// cryptlib 3.4.9.6 fail with an internal error on the third entry added.
		if (cCert.GetContactEmailAddress() != null)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_RFC822NAME, cCert.GetContactEmailAddress());
		}
		foreach (string dnsName in cCert.GetDNSName())
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_DNSNAME, dnsName);
		}
		if (cCert.GetURIName() != null)
		{
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_UNIFORMRESOURCEIDENTIFIER, cCert.GetURIName());
		}
		if (cCert.GetIPAddress() != null)
		{
			byte[] addressBytes = IPAddress.Parse(cCert.GetIPAddress()).GetAddressBytes();
			crypt.SetAttributeString(certRequest, crypt.CERTINFO_IPADDRESS, addressBytes);
		}
	}

	private static void AttachAPCFileHeader(string file, Globals._FlashFileFileType eType)
	{
		NMCHeader nMCHeader = new NMCHeader();
		byte[] array = File.ReadAllBytes(file);
		List<byte> list = new List<byte>();
		if (!File.Exists(file))
		{
			return;
		}
		list.InsertRange(0, array);
		nMCHeader.headerVersion = 1;
		nMCHeader.appVersion = 1;
		nMCHeader.appVersionStr = "NMCSecurityWizardCLI100".PadRight(200, '\0').ToCharArray();
		nMCHeader.fileVersion = 1;
		nMCHeader.fileType = (int)eType;
		nMCHeader.fileSize = list.Count;
		nMCHeader.fileCrc = BitConverter.ToInt32(NMCHeader.ComputeRhodesChecksum(array), 0);
		nMCHeader.headerCrc = BitConverter.ToInt32(NMCHeader.ComputeRhodesChecksum(nMCHeader.CreateByteArray(bIncludeHeaderCrc: false)), 0);
		byte[] array2 = nMCHeader.CreateByteArray(bIncludeHeaderCrc: true);
		using FileStream fileStream = new FileStream(file, FileMode.Create);
		for (int i = 0; i < array2.Length; i++)
		{
			fileStream.WriteByte(array2[i]);
		}
		for (int j = 0; j < array.Length; j++)
		{
			fileStream.WriteByte(array[j]);
		}
	}

	private static void DisplayCertificateSummary(int iContextIn)
	{
		crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT, crypt.CERTINFO_ISSUERNAME);
		Console.WriteLine("Certificate's Issuer Information:");
		DisplayCertificateElements(iContextIn, Globals._CertificateGroup.GroupIssuer);
		Console.WriteLine("");
		crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT, crypt.CERTINFO_SUBJECTNAME);
		Console.WriteLine("Certificate's Subject Information:");
		DisplayCertificateElements(iContextIn, Globals._CertificateGroup.GroupSubject);
		Console.WriteLine("");
		crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT, crypt.CERTINFO_SUBJECTNAME);
		Console.WriteLine("Certificate's General Information:");
		DisplayCertificateElements(iContextIn, Globals._CertificateGroup.GroupGeneral);
		Console.WriteLine("");
	}

	private static void DisplayCertificateElements(int iContextIn, Globals._CertificateGroup eGroup)
	{
		int num = 0;
		switch (eGroup)
		{
		case Globals._CertificateGroup.GroupIssuer:
		case Globals._CertificateGroup.GroupSubject:
			try
			{
				Console.WriteLine("  Common Name: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_COMMONNAME));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Country: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_COUNTRYNAME));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  State/Province: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_STATEORPROVINCENAME));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Locality: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_LOCALITYNAME));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Organization: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_ORGANIZATIONNAME));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Organizational Unit: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_ORGANIZATIONALUNITNAME));
			}
			catch (CryptException)
			{
			}
			if (eGroup == Globals._CertificateGroup.GroupSubject)
			{
				try
				{
					num = crypt.GetAttributeString(iContextIn, crypt.CERTINFO_VALIDFROM, null);
					byte[] value = new byte[num];
					crypt.GetAttributeString(iContextIn, crypt.CERTINFO_VALIDFROM, value);
					Console.WriteLine("  Valid From: " + Globals.ConvertSecondsToTimeStamp(BitConverter.ToInt64(value, 0)) + " (GMT)");
				}
				catch (CryptException)
				{
				}
				try
				{
					num = crypt.GetAttributeString(iContextIn, crypt.CERTINFO_VALIDTO, null);
					byte[] value2 = new byte[num];
					crypt.GetAttributeString(iContextIn, crypt.CERTINFO_VALIDTO, value2);
					Console.WriteLine("  Valid To: " + Globals.ConvertSecondsToTimeStamp(BitConverter.ToInt64(value2, 0)) + " (GMT)");
				}
				catch (CryptException)
				{
				}
				try
				{
					Console.WriteLine("  E-Mail Address: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_RFC822NAME));
				}
				catch (CryptException)
				{
				}
				try
				{
					Console.WriteLine("  URI Name: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_UNIFORMRESOURCEIDENTIFIER));
				}
				catch (CryptException)
				{
				}
				try
				{
					byte[] array3 = new byte[4];
					crypt.GetAttributeString(iContextIn, crypt.CERTINFO_IPADDRESS, array3);
					Console.WriteLine("  IP Address: " + new IPAddress(array3).ToString());
				}
				catch (CryptException)
				{
				}
				try
				{
					crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT, crypt.CERTINFO_SUBJECTALTNAME);
					crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT_INSTANCE, crypt.CERTINFO_DNSNAME);
					// Stepping past the last instance throws, which ends the loop.
					while (true)
					{
						Console.WriteLine("  DNS Name: " + crypt.GetAttributeString(iContextIn, crypt.CERTINFO_DNSNAME));
						crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT_INSTANCE, crypt.CURSOR_NEXT);
					}
				}
				catch (CryptException)
				{
				}
				break;
			}
			break;
		case Globals._CertificateGroup.GroupGeneral:
			try
			{
				num = crypt.GetAttributeString(iContextIn, crypt.CERTINFO_SERIALNUMBER, null);
				byte[] array = new byte[num];
				crypt.GetAttributeString(iContextIn, crypt.CERTINFO_SERIALNUMBER, array);
				Console.WriteLine("  Serial Number: " + BitConverter.ToString(array).Replace("-", ":"));
			}
			catch (CryptException)
			{
			}
			try
			{
				num = crypt.GetAttributeString(iContextIn, crypt.CERTINFO_FINGERPRINT_SHA1, null);
				byte[] array2 = new byte[num];
				crypt.GetAttributeString(iContextIn, crypt.CERTINFO_FINGERPRINT_SHA1, array2);
				Console.WriteLine("  SHA1 Thumbprint: " + BitConverter.ToString(array2).Replace("-", ":"));
				break;
			}
			catch (CryptException)
			{
				break;
			}
		}
	}

	private static void DisplaySplashHeader()
	{
		Console.WriteLine("");
		Console.WriteLine("NMC Security Wizard Command Line Utility v1.0.7");
		Console.WriteLine("(c) Copyright 2018 Schneider Electric. All rights reserved.");
		Console.WriteLine("-----------------------------------------------------------------------------");
	}

	private static void DisplayCommandLineSyntax()
	{
		Console.WriteLine("Usage:");
		Console.WriteLine("  NMCSecurityWizardCLI --sslcert -o <file> -r <file> -n <common_name>");
		Console.WriteLine("                       -c <country> [-m <state_province> -l <locality>");
		Console.WriteLine("                       -g <organization> -u <organizational_unit> -e <email>");
		Console.WriteLine("                       -f <validity_from> -t <validity_to> -i <uri_name>");
		Console.WriteLine("                       -d <dns_name> -a <ip_address>]");
		Console.WriteLine("  NMCSecurityWizardCLI --sshkey -o <file>");
		Console.WriteLine("  NMCSecurityWizardCLI --caroot -o <file> -n <common_name> -c <country>");
		Console.WriteLine("                       [-m <state_province> -l <locality> -g <organization>");
		Console.WriteLine("                       -u <organizational_unit> -e <email> -f <validity_from>");
		Console.WriteLine("                       -t <validity_to> -i <uri_name> -d <dns_name>");
		Console.WriteLine("                       -a <ip_address>]");
		Console.WriteLine("  NMCSecurityWizardCLI --csr -o <file> -n <common_name> -c <country>");
		Console.WriteLine("                       [-m <state_province> -l <locality> -g <organization>");
		Console.WriteLine("                       -u <organizational_unit> -e <email> -i <uri_name>");
		Console.WriteLine("                       -d <dns_name> -a <ip_address>]");
		Console.WriteLine("  NMCSecurityWizardCLI --import -o <file> -s <file> -p <file>");
		Console.WriteLine("");
		Console.WriteLine("Options:");
		Console.WriteLine("  --sslcert  Creates a SSL server certificate");
		Console.WriteLine("  --sshkey   Creates a SSH server host key");
		Console.WriteLine("  --caroot   Creates a CA root certificate");
		Console.WriteLine("  --csr      Creates one or more cert signing requests");
		Console.WriteLine("  --import   Creates a NMC certificate based on signed cert and private key");
		Console.WriteLine("");
		Console.WriteLine("  -o         Output file (without extension)");
		Console.WriteLine("  -r         CA Root Certificate .p15 input file (without extension)");
		Console.WriteLine("  -s         Signed Certificate .crt/.cer input file (with extension)");
		Console.WriteLine("  -p         Private Key .p15 input file (without extension)");
		Console.WriteLine("  -n         Common Name (DN Attribute) * Required");
		Console.WriteLine("  -c         Country Code (DN Attribute) * Required");
		Console.WriteLine("  -m         State or Province (DN Attribute)");
		Console.WriteLine("  -l         Locality (DN Attribute)");
		Console.WriteLine("  -g         Organization (DN Attribute)");
		Console.WriteLine("  -u         Organizational Unit (DN Attribute)");
		Console.WriteLine("  -f         Validity From (DN Attribute) [mm/dd/yyyy]");
		Console.WriteLine("  -t         Validity To (DN Attribute) [mm/dd/yyyy]");
		Console.WriteLine("  -e         Contact Email Address (SAN Attribute)");
		Console.WriteLine("  -i         URI Name (SAN Attribute)");
		Console.WriteLine("  -d         DNS Name (SAN Attribute, repeatable)");
		Console.WriteLine("  -a         IP Address (SAN Attribute)");
		Console.WriteLine("");
		Console.WriteLine("  -k         Key Size [1024 | 2048]");
	}
}

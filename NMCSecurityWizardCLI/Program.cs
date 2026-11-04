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
		crypt.SetAttribute(-101, 107, 205);
		crypt.SetAttribute(-101, 106, 2);
		crypt.SetAttribute(-101, 118, 1);
		crypt.SetAttribute(-101, 114, 5000);
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
		int num = crypt.CreateContext(-101, 101);
		crypt.SetAttribute(num, 1005, cCertIn.GetKeySize() / 8);
		crypt.SetAttributeString(num, 1016, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(-101, 1, cCertIn.GetFileName() + ".p15", 2);
		crypt.AddPrivateKey(keyset, num, "user");
		int num2 = crypt.CreateCert(-101, 4);
		crypt.SetAttribute(num2, 2014, num);
		SetDNAttributes(num2, cCertIn, bUseValidity: false);
		SetSANAttributes(num2, cCertIn);
		crypt.SignCert(num2, num);
		int keyset2;
		try
		{
			keyset2 = crypt.KeysetOpen(-101, 1, sCaRootCertIn + ".p15", 1);
		}
		catch (CryptException)
		{
			crypt.KeysetClose(keyset);
			crypt.DestroyContext(num);
			crypt.DestroyCert(num2);
			File.Delete(cCertIn.GetFileName() + ".p15");
			return false;
		}
		int privateKey = crypt.GetPrivateKey(keyset2, 1, "Private key", "root");
		crypt.KeysetClose(keyset2);
		int num3 = crypt.CreateCert(-101, 1);
		crypt.SetAttribute(num3, 2023, num2);
		if (cCertIn.GetValidityPeriodStart() != 0 && cCertIn.GetValidityPeriodEnd() != 0)
		{
			crypt.SetAttributeString(num3, 2018, BitConverter.GetBytes((int)cCertIn.GetValidityPeriodStart()));
			crypt.SetAttributeString(num3, 2019, BitConverter.GetBytes((int)cCertIn.GetValidityPeriodEnd()));
		}
		crypt.SignCert(num3, privateKey);
		crypt.AddPublicKey(keyset, num3);
		int num4 = crypt.ExportCert(null, 0, 1, num3);
		byte[] array = new byte[num4];
		crypt.ExportCert(array, array.Length, 1, num3);
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
		int num = crypt.CreateContext(-101, 101);
		crypt.SetAttribute(num, 1005, cCertIn.GetKeySize() / 8);
		crypt.SetAttributeString(num, 1016, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(-101, 1, cCertIn.GetFileName() + ".p15", 2);
		crypt.AddPrivateKey(keyset, num, "user");
		crypt.KeysetClose(keyset);
		int num2 = crypt.CreateCert(-101, 4);
		crypt.SetAttribute(num2, 2014, num);
		SetDNAttributes(num2, cCertIn, bUseValidity: false);
		SetSANAttributes(num2, cCertIn);
		crypt.SignCert(num2, num);
		crypt.DestroyContext(num);
		int num3 = crypt.ExportCert(null, 0, 3, num2);
		byte[] array = new byte[num3 + 1];
		crypt.ExportCert(array, array.Length, 3, num2);
		crypt.DestroyCert(num2);
		File.WriteAllBytes(cCertIn.GetFileName() + ".csr", array);
		return true;
	}

	private static bool CreateSSHServerHostKey(string sOutFile, int sKeySize)
	{
		int num = crypt.CreateContext(-101, 101);
		crypt.SetAttribute(num, 1005, sKeySize / 8);
		crypt.SetAttributeString(num, 1016, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(-101, 1, sOutFile + ".p15", 2);
		crypt.AddPrivateKey(keyset, num, "user");
		crypt.KeysetClose(keyset);
		crypt.DestroyContext(num);
		AttachAPCFileHeader(sOutFile + ".p15", Globals._FlashFileFileType.SSHKey);
		return true;
	}

	private static bool CreateCARootCert(Certificate cCertIn)
	{
		int num = crypt.CreateContext(-101, 101);
		crypt.SetAttribute(num, 1005, cCertIn.GetKeySize() / 8);
		crypt.SetAttributeString(num, 1016, Encoding.ASCII.GetBytes("Private key"), 0, 11);
		crypt.GenerateKey(num);
		int keyset = crypt.KeysetOpen(-101, 1, cCertIn.GetFileName() + ".p15", 2);
		crypt.AddPrivateKey(keyset, num, "root");
		crypt.KeysetClose(keyset);
		int num2 = crypt.CreateCert(-101, 1);
		crypt.SetAttribute(num2, 2014, num);
		SetDNAttributes(num2, cCertIn, bUseValidity: true);
		SetSANAttributes(num2, cCertIn);
		crypt.SetAttribute(num2, 2001, 1);
		crypt.SetAttribute(num2, 2266, 96);
		crypt.SetAttribute(num2, 2273, 1);
		crypt.SignCert(num2, num);
		crypt.DestroyContext(num);
		keyset = crypt.KeysetOpen(-101, 1, cCertIn.GetFileName() + ".p15", 0);
		crypt.AddPublicKey(keyset, num2);
		crypt.KeysetClose(keyset);
		int num3 = crypt.ExportCert(null, 0, 1, num2);
		byte[] array = new byte[num3];
		crypt.ExportCert(array, array.Length, 1, num2);
		File.WriteAllBytes(cCertIn.GetFileName() + ".crt", array);
		DisplayCertificateSummary(num2);
		crypt.DestroyCert(num2);
		return true;
	}

	private static bool ImportSignedCSR(string sCertFile, string sKeyFile, string sOutFile)
	{
		File.WriteAllBytes(sOutFile + ".p15", File.ReadAllBytes(sKeyFile + ".p15"));
		byte[] certObject = File.ReadAllBytes(sCertFile);
		int num = crypt.ImportCert(certObject, -101);
		int keyset = crypt.KeysetOpen(-101, 1, sOutFile + ".p15", 0);
		crypt.AddPublicKey(keyset, num);
		crypt.KeysetClose(keyset);
		DisplayCertificateSummary(num);
		crypt.DestroyCert(num);
		AttachAPCFileHeader(sOutFile + ".p15", Globals._FlashFileFileType.SSLServerCert);
		return true;
	}

	private static void SetDNAttributes(int certRequest, Certificate cCert, bool bUseValidity)
	{
		crypt.SetAttributeString(certRequest, 2105, cCert.GetCommonName());
		crypt.SetAttributeString(certRequest, 2100, cCert.GetCountry());
		if (cCert.GetStateOrProvince() != null)
		{
			crypt.SetAttributeString(certRequest, 2101, cCert.GetStateOrProvince());
		}
		if (cCert.GetLocality() != null)
		{
			crypt.SetAttributeString(certRequest, 2102, cCert.GetLocality());
		}
		if (cCert.GetOrganization() != null)
		{
			crypt.SetAttributeString(certRequest, 2103, cCert.GetOrganization());
		}
		if (cCert.GetOrganizationalUnit() != null)
		{
			crypt.SetAttributeString(certRequest, 2104, cCert.GetOrganizationalUnit());
		}
		if (bUseValidity && cCert.GetValidityPeriodStart() != 0 && cCert.GetValidityPeriodEnd() != 0)
		{
			crypt.SetAttributeString(certRequest, 2018, BitConverter.GetBytes((int)cCert.GetValidityPeriodStart()));
			crypt.SetAttributeString(certRequest, 2019, BitConverter.GetBytes((int)cCert.GetValidityPeriodEnd()));
		}
	}

	private static void SetSANAttributes(int certRequest, Certificate cCert)
	{
		crypt.SetAttribute(certRequest, 14, 2270);
		if (cCert.GetContactEmailAddress() != null)
		{
			crypt.SetAttributeString(certRequest, 2108, cCert.GetContactEmailAddress());
		}
		foreach (string dnsName in cCert.GetDNSName())
		{
			crypt.SetAttributeString(certRequest, 2109, dnsName);
		}
		if (cCert.GetURIName() != null)
		{
			crypt.SetAttributeString(certRequest, 2113, cCert.GetURIName());
		}
		if (cCert.GetIPAddress() != null)
		{
			byte[] addressBytes = IPAddress.Parse(cCert.GetIPAddress()).GetAddressBytes();
			crypt.SetAttributeString(certRequest, 2114, addressBytes);
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
		crypt.SetAttribute(iContextIn, 14, 2017);
		Console.WriteLine("Certificate's Issuer Information:");
		DisplayCertificateElements(iContextIn, Globals._CertificateGroup.GroupIssuer);
		Console.WriteLine("");
		crypt.SetAttribute(iContextIn, 14, 2020);
		Console.WriteLine("Certificate's Subject Information:");
		DisplayCertificateElements(iContextIn, Globals._CertificateGroup.GroupSubject);
		Console.WriteLine("");
		crypt.SetAttribute(iContextIn, 14, 2020);
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
				Console.WriteLine("  Common Name: " + crypt.GetAttributeString(iContextIn, 2105));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Country: " + crypt.GetAttributeString(iContextIn, 2100));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  State/Province: " + crypt.GetAttributeString(iContextIn, 2101));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Locality: " + crypt.GetAttributeString(iContextIn, 2102));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Organization: " + crypt.GetAttributeString(iContextIn, 2103));
			}
			catch (CryptException)
			{
			}
			try
			{
				Console.WriteLine("  Organizational Unit: " + crypt.GetAttributeString(iContextIn, 2104));
			}
			catch (CryptException)
			{
			}
			if (eGroup == Globals._CertificateGroup.GroupSubject)
			{
				try
				{
					num = crypt.GetAttributeString(iContextIn, 2018, null);
					byte[] value = new byte[num];
					crypt.GetAttributeString(iContextIn, 2018, value);
					Console.WriteLine("  Valid From: " + Globals.ConvertSecondsToTimeStamp(BitConverter.ToInt32(value, 0)) + " (GMT)");
				}
				catch (CryptException)
				{
				}
				try
				{
					num = crypt.GetAttributeString(iContextIn, 2019, null);
					byte[] value2 = new byte[num];
					crypt.GetAttributeString(iContextIn, 2019, value2);
					Console.WriteLine("  Valid To: " + Globals.ConvertSecondsToTimeStamp(BitConverter.ToInt32(value2, 0)) + " (GMT)");
				}
				catch (CryptException)
				{
				}
				try
				{
					Console.WriteLine("  E-Mail Address: " + crypt.GetAttributeString(iContextIn, 2108));
				}
				catch (CryptException)
				{
				}
				try
				{
					Console.WriteLine("  URI Name: " + crypt.GetAttributeString(iContextIn, 2113));
				}
				catch (CryptException)
				{
				}
				try
				{
					byte[] array3 = new byte[4];
					crypt.GetAttributeString(iContextIn, 2114, array3);
					Console.WriteLine("  IP Address: " + new IPAddress(array3).ToString());
				}
				catch (CryptException)
				{
				}
				try
				{
					crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT, crypt.CERTINFO_SUBJECTALTNAME);
					crypt.SetAttribute(iContextIn, crypt.ATTRIBUTE_CURRENT, crypt.CERTINFO_DNSNAME);
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
				num = crypt.GetAttributeString(iContextIn, 2013, null);
				byte[] array = new byte[num];
				crypt.GetAttributeString(iContextIn, 2013, array);
				Console.WriteLine("  Serial Number: " + BitConverter.ToString(array).Replace("-", ":"));
			}
			catch (CryptException)
			{
			}
			try
			{
				num = crypt.GetAttributeString(iContextIn, 2005, null);
				byte[] array2 = new byte[num];
				crypt.GetAttributeString(iContextIn, 2005, array2);
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
		Console.WriteLine("NMC Security Wizard Command Line Utility v1.0.5");
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

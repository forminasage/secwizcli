using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace NMCSecurityWizardCLI;

internal class ArgsParser
{
	private string[] commandLineArgs;

	public Globals._FunctionType functionType { get; set; }

	public string outputFile { get; set; }

	public int keySize { get; set; }

	public string caRootCertIn { get; set; }

	public string signedCertIn { get; set; }

	public string privKeyIn { get; set; }

	public string commonNameDN { get; set; }

	public string countryDN { get; set; }

	public string stateProvinceDN { get; set; }

	public string localityDN { get; set; }

	public string organizationDN { get; set; }

	public string organizationalUnitDN { get; set; }

	public long validityFromDN { get; set; }

	public long validityToDN { get; set; }

	public string emailAddressSAN { get; set; }

	public List<string> dnsNameSAN { get; } = new List<string>();

	public string uriNameSAN { get; set; }

	public string ipAddressSAN { get; set; }

	public ArgsParser(string[] sArgs)
	{
		commandLineArgs = sArgs;
		functionType = Globals._FunctionType.Unknown;
		keySize = 2048;
	}

	public Globals._ParseError ProcessCommandLineArgs()
	{
		for (int i = 0; i < commandLineArgs.Length; i++)
		{
			switch (commandLineArgs[i])
			{
			case "--sslcert":
				functionType = Globals._FunctionType.CreateSSLCert;
				break;
			case "--sshkey":
				functionType = Globals._FunctionType.CreateSSHKey;
				break;
			case "--caroot":
				functionType = Globals._FunctionType.CreateCARootCert;
				break;
			case "--csr":
				functionType = Globals._FunctionType.CreateCSR;
				break;
			case "--import":
				functionType = Globals._FunctionType.ImportCert;
				break;
			case "-a":
				try
				{
					ipAddressSAN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				catch (FormatException)
				{
					return Globals._ParseError.ParseErrorIPAddress;
				}
				break;
			case "-c":
				try
				{
					countryDN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				if (countryDN.Length != 2)
				{
					return Globals._ParseError.ParseErrorCountryCode;
				}
				try
				{
					new RegionInfo(countryDN);
				}
				catch (ArgumentException)
				{
					return Globals._ParseError.ParseErrorCountryCode;
				}
				break;
			case "-d":
				try
				{
					dnsNameSAN.Add(commandLineArgs[++i]);
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				catch (FormatException)
				{
					return Globals._ParseError.ParseErrorDNSName;
				}
				break;
			case "-e":
				try
				{
					emailAddressSAN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				if (!emailAddressSAN.Contains("@") || !emailAddressSAN.Contains("."))
				{
					return Globals._ParseError.ParseErrorEmailAddress;
				}
				break;
			case "-f":
				try
				{
					validityFromDN = Globals.ConvertTimeStampToSeconds(commandLineArgs[++i]);
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				catch (FormatException)
				{
					return Globals._ParseError.ParseErrorTimestampFormat;
				}
				break;
			case "-g":
				try
				{
					organizationDN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-i":
				try
				{
					if (Uri.IsWellFormedUriString(commandLineArgs[i + 1], UriKind.RelativeOrAbsolute))
					{
						uriNameSAN = commandLineArgs[++i];
						break;
					}
					return Globals._ParseError.ParseErrorURIName;
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				catch (FormatException)
				{
					return Globals._ParseError.ParseErrorURIName;
				}
			case "-k":
				try
				{
					keySize = Convert.ToInt32(commandLineArgs[++i]);
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				catch (FormatException)
				{
					return Globals._ParseError.ParseErrorKeySize;
				}
				if (keySize != 1024 && keySize != 2048)
				{
					return Globals._ParseError.ParseErrorKeySize;
				}
				break;
			case "-l":
				try
				{
					localityDN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-m":
				try
				{
					stateProvinceDN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-n":
				try
				{
					commonNameDN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-o":
				try
				{
					outputFile = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-p":
				try
				{
					privKeyIn = commandLineArgs[++i];
					if (!File.Exists(privKeyIn + ".p15"))
					{
						return Globals._ParseError.ParseErrorKeyDoesNotExist;
					}
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-r":
				try
				{
					caRootCertIn = commandLineArgs[++i];
					if (!File.Exists(caRootCertIn + ".p15"))
					{
						return Globals._ParseError.ParseErrorCARootDoesNotExist;
					}
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-s":
				try
				{
					signedCertIn = commandLineArgs[++i];
					if (!File.Exists(signedCertIn))
					{
						return Globals._ParseError.ParseErrorSignedCertDoesNotExist;
					}
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			case "-t":
				try
				{
					validityToDN = Globals.ConvertTimeStampToSeconds(commandLineArgs[++i]);
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				catch (FormatException)
				{
					return Globals._ParseError.ParseErrorTimestampFormat;
				}
				break;
			case "-u":
				try
				{
					organizationalUnitDN = commandLineArgs[++i];
				}
				catch (IndexOutOfRangeException)
				{
					return Globals._ParseError.ParseErrorArgumentMismatch;
				}
				break;
			default:
				return Globals._ParseError.ParseErrorUnknownArgument;
			}
		}
		if (!ValidateArgumentValues())
		{
			return Globals._ParseError.ParseFunctionArgsIncomplete;
		}
		if ((validityFromDN > 0 || validityToDN > 0) && validityFromDN > validityToDN)
		{
			return Globals._ParseError.ParseErrorTimestampRange;
		}
		return Globals._ParseError.ParseErrorNone;
	}

	private bool ValidateArgumentValues()
	{
		switch (functionType)
		{
		case Globals._FunctionType.CreateSSLCert:
			if (outputFile == null || caRootCertIn == null || commonNameDN == null || countryDN == null)
			{
				return false;
			}
			break;
		case Globals._FunctionType.CreateSSHKey:
			if (outputFile == null)
			{
				return false;
			}
			break;
		case Globals._FunctionType.CreateCARootCert:
			if (outputFile == null || commonNameDN == null || countryDN == null)
			{
				return false;
			}
			break;
		case Globals._FunctionType.CreateCSR:
			if (outputFile == null || commonNameDN == null || countryDN == null)
			{
				return false;
			}
			break;
		case Globals._FunctionType.ImportCert:
			if (outputFile == null || signedCertIn == null || privKeyIn == null)
			{
				return false;
			}
			break;
		default:
			return false;
		}
		return true;
	}
}

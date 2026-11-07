using System;
using System.Globalization;

namespace NMCSecurityWizardCLI;

public static class Globals
{
	public enum _LogStorage
	{
		LogResult,
		LogError,
		LogResultError
	}

	public enum _FunctionType
	{
		CreateSSLCert,
		CreateSSHKey,
		CreateCARootCert,
		CreateCSR,
		ImportCert,
		Unknown
	}

	public enum _FlashFileFileType
	{
		SSLServerCert = 1,
		SSLCLICert,
		SSHKey,
		CustomType
	}

	public enum _CertificateGroup
	{
		GroupIssuer,
		GroupSubject,
		GroupGeneral
	}

	public enum _ParseError
	{
		ParseErrorNone,
		ParseFunctionArgsIncomplete,
		ParseErrorArgumentMismatch,
		ParseErrorUnknownArgument,
		ParseErrorTimestampFormat,
		ParseErrorTimestampRange,
		ParseErrorKeySize,
		ParseErrorEmailAddress,
		ParseErrorURIName,
		ParseErrorDNSName,
		ParseErrorIPAddress,
		ParseErrorCountryCode,
		ParseErrorInvalidFileName,
		ParseErrorKeyDoesNotExist,
		ParseErrorCARootDoesNotExist,
		ParseErrorSignedCertDoesNotExist
	}

	public const string _appVersionIdentifier = "1.0.6";

	public const string _appNameIdentifier = "NMCSecurityWizardCLI100";

	public const string _contextKeysetLabel = "Private key";

	public const string _contextKeysetRootPassword = "root";

	public const string _contextKeysetUserPassword = "user";

	public const string _certDefaultFilename = "Cert1";

	public const int _certDefaultKeySize = 2048;

	public const string _certDefaultCommonName = "HostName.Example.com";

	public const string _certDefaultCountry = "US";

	public const string _certDefaultStateOrProvince = "Massachusetts";

	public const string _certDefaultLocality = "Andover";

	public const string _certDefaultOrganization = "Company Name";

	public const string _certDefaultOrganizationalUnit = "Company Division";

	public const string _certDefaultValidityPeriodStart = "01/01/2016";

	public const string _certDefaultValidityPeriodEnd = "01/01/2017";

	public const string _certDefaultEmailAddress = "john.doe@example.com";

	public const string _certDefaultURIName = "https://api.example.com";

	public const string _certDefaultDNSName = "HostName.Example.com";

	public const string _certDefaultIPAddress = "127.0.0.1";

	public const int _certKeyingIterations = 5000;

	public const string _resultLogFileName = "result.log";

	public const string _errorLogFileName = "error.log";

	public const string _LogFolderTimestampFormat = "yyyy-MM-ddTHHmmss";

	public const string _event_appStarted = "NMC Security Wizard Command Line Utility v{0} initialized.";

	public const string _event_argumentIncomplete = "One or more arguments are missing. Please verify and retry.";

	public const string _event_argumentUnknown = "One or more arguments entered is unknown. Please verify and retry.";

	public const string _event_argumentInvalid = "{0} parameter has been entered incorrectly. Please verify and retry.";

	public const string _event_filenameInvalid = "Filename '{0}' does not meet the supported naming convention. Please verify and retry.";

	public const string _event_filenameDoesNotExist = "Input file '{0}.p15' does not exist. Please verify and retry.";

	public const string _event_sslServerCertSuccess = "SSL certificate '{0}' has been successfully created.";

	public const string _event_sslServerCertFailure = "SSL certificate '{0}' could not be generated; recheck settings.";

	public const string _event_sshHostKeySuccess = "SSH host key '{0}' has been successfully created.";

	public const string _event_sshHostKeyFailure = "SSH host key '{0}' could not be generated; recheck settings.";

	public const string _event_caRootCertSuccess = "CA root cert and private key '{0}' have been successfully created.";

	public const string _event_caRootCertFailure = "CA root cert and private key '{0}' could not be generated; recheck settings.";

	public const string _event_certSingleCSRSuccess = "CSR and private key '{0}' have been successfully created.";

	public const string _event_certSingleCSRFailure = "CSR and private key '{0}' could not be generated; recheck settings.";

	public const string _event_certMultCSRSuccess = "CSR and private key {0} were created from the certificate input file.";

	public const string _event_certMultCSRFailure = "CSR and private key {0} failed to be created from the certificate input file.";

	public const string _event_CSRFileProcessingCompleteSuccess = "Certificate processing complete; {0} CSR(s) successfully generated.";

	public const string _event_CSRFileProcessingCompleteFailure = "Certificate processing encountered errors; recheck input file.";

	public const string _event_importCertSuccess = "Importing certificate '{0}' has successfully completed.";

	public const string _event_importCertFailure = "Importing certificate '{0}' could not be completed; recheck settings.";

	public const string _event_timestampRangeInvalid = "Validity 'From' and 'To' dates are not in range. Please verify and retry.";

	public static long ConvertTimeStampToSeconds(string sTimeStampIn)
	{
		DateTime dateTime = new DateTime(1970, 1, 1, 0, 0, 0);
		DateTime dateTime2 = DateTime.ParseExact(sTimeStampIn, "MM/dd/yyyy", CultureInfo.InvariantCulture);
		_ = (dateTime2.Ticks - dateTime.Ticks) / 10000000;
		return (dateTime2.Ticks - dateTime.Ticks) / 10000000;
	}

	public static string ConvertSecondsToTimeStamp(long lSecondsIn)
	{
		return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(Convert.ToDouble(lSecondsIn)).ToString("MM/dd/yyyy");
	}
}

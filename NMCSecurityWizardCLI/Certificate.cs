using System.Collections.Generic;

namespace NMCSecurityWizardCLI;

internal class Certificate
{
	private string filename;

	private int keySize;

	private string commonName;

	private string country;

	private string stateOrProvince;

	private string locality;

	private string organization;

	private string organizationalUnit;

	private long validityPeriodStart;

	private long validtyPeriodEnd;

	private string contactEmailAddress;

	private string uriName;

	private List<string> dnsName;

	private string ipAddress;

	public Certificate()
	{
		keySize = 2048;
	}

	public Certificate(string sFilename, int iKeySize, string sCommonName, string sCountry, string sState, string sLocality, string sOrg, string sOrgUnit, long sValidityStart, long sValidityEnd, string sEmail, string sUriName, List<string> sDnsName, string sIpAddress)
	{
		filename = sFilename;
		keySize = iKeySize;
		commonName = sCommonName;
		country = sCountry;
		stateOrProvince = sState;
		locality = sLocality;
		organization = sOrg;
		organizationalUnit = sOrgUnit;
		validityPeriodStart = sValidityStart;
		validtyPeriodEnd = sValidityEnd;
		contactEmailAddress = sEmail;
		uriName = sUriName;
		dnsName = sDnsName;
		ipAddress = sIpAddress;
	}

	public string GetFileName()
	{
		return filename;
	}

	public bool SetFileName(string sFileName)
	{
		filename = sFileName;
		return true;
	}

	public int GetKeySize()
	{
		return keySize;
	}

	public bool SetKeySize(int iKeySize)
	{
		if (iKeySize == 1024 || iKeySize == 2048 || iKeySize == 4096)
		{
			keySize = iKeySize;
			return true;
		}
		return false;
	}

	public string GetCommonName()
	{
		return commonName;
	}

	public bool SetCommonName(string sCommonName)
	{
		commonName = sCommonName;
		return true;
	}

	public string GetCountry()
	{
		return country;
	}

	public bool SetCountry(string sCountry)
	{
		country = sCountry;
		return true;
	}

	public string GetStateOrProvince()
	{
		return stateOrProvince;
	}

	public bool SetStateOrProvince(string sStateOrProvince)
	{
		stateOrProvince = sStateOrProvince;
		return true;
	}

	public string GetLocality()
	{
		return locality;
	}

	public bool SetLocality(string sLocality)
	{
		locality = sLocality;
		return true;
	}

	public string GetOrganization()
	{
		return organization;
	}

	public bool SetOrganization(string sOrganization)
	{
		organization = sOrganization;
		return true;
	}

	public string GetOrganizationalUnit()
	{
		return organizationalUnit;
	}

	public bool SetOrganizationalUnit(string sOrganizationalUnit)
	{
		organizationalUnit = sOrganizationalUnit;
		return true;
	}

	public long GetValidityPeriodStart()
	{
		return validityPeriodStart;
	}

	public bool SetValidityPeriodStart(long sValidityPeriodStart)
	{
		validityPeriodStart = sValidityPeriodStart;
		return true;
	}

	public long GetValidityPeriodEnd()
	{
		return validtyPeriodEnd;
	}

	public bool SetValidityPeriodEnd(long sValidityPeriodEnd)
	{
		validtyPeriodEnd = sValidityPeriodEnd;
		return true;
	}

	public string GetContactEmailAddress()
	{
		return contactEmailAddress;
	}

	public bool SetContactEmailAddress(string sContactEmailAddress)
	{
		contactEmailAddress = sContactEmailAddress;
		return true;
	}

	public string GetURIName()
	{
		return uriName;
	}

	public bool SetURIName(string sUriName)
	{
		uriName = sUriName;
		return true;
	}

	public List<string> GetDNSName()
	{
		return dnsName;
	}

	public string GetIPAddress()
	{
		return ipAddress;
	}

	public bool SetIPAddress(string sIpAddress)
	{
		ipAddress = sIpAddress;
		return true;
	}

	public bool CheckForCompleteEntry()
	{
		if (filename == null || commonName == null || country == null)
		{
			return false;
		}
		return true;
	}
}

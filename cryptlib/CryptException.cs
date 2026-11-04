using System;

namespace cryptlib;

public class CryptException : ApplicationException
{
	public int Status => (int)Data["Status"];

	public int ExtraInfo => (int)Data["ExtraInfo"];

	public CryptException(int status)
		: base(convertMessage(status))
	{
		Data.Add("Status", status);
	}

	public CryptException(int status, int extra)
		: base(convertMessage(status))
	{
		Data.Add("Status", status);
		Data.Add("ExtraInfo", extra);
	}

	private static string convertMessage(int status)
	{
		string text = Convert.ToString(status) + ": ";
		return status switch
		{
			-1 => text + "Bad argument, parameter 1", 
			-2 => text + "Bad argument, parameter 2", 
			-3 => text + "Bad argument, parameter 3", 
			-4 => text + "Bad argument, parameter 4", 
			-5 => text + "Bad argument, parameter 5", 
			-6 => text + "Bad argument, parameter 6", 
			-7 => text + "Bad argument, parameter 7", 
			-10 => text + "Out of memory", 
			-11 => text + "Data has not been initialised", 
			-12 => text + "Data has already been init'd", 
			-13 => text + "Opn.not avail.at requested sec.level", 
			-14 => text + "No reliable random data available", 
			-15 => text + "Operation failed", 
			-16 => text + "Internal consistency check failed", 
			-20 => text + "This type of opn.not available", 
			-21 => text + "No permiss.to perform this operation", 
			-22 => text + "Incorrect key used to decrypt data", 
			-23 => text + "Operation incomplete/still in progress", 
			-24 => text + "Operation complete/can't continue", 
			-25 => text + "Operation timed out before completion", 
			-26 => text + "Invalid/inconsistent information", 
			-27 => text + "Resource destroyed by extnl.event", 
			-30 => text + "Resources/space exhausted", 
			-31 => text + "Not enough data available", 
			-32 => text + "Bad/unrecognised data format", 
			-33 => text + "Signature/integrity check failed", 
			-40 => text + "Cannot open object", 
			-41 => text + "Cannot read item from object", 
			-42 => text + "Cannot write item to object", 
			-43 => text + "Requested item not found in object", 
			-44 => text + "Item already present in object", 
			-50 => text + "Need resource to proceed", 
			_ => text + "Unknown Exception ?!?!", 
		};
	}
}

using System.Runtime.InteropServices;

namespace cryptlib;

[StructLayout(LayoutKind.Sequential)]
public class CRYPT_QUERY_INFO
{
	[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
	public string algoName;

	public int blockSize;

	public int minKeySize;

	public int keySize;

	public int maxKeySize;

	public CRYPT_QUERY_INFO()
	{
	}

	public CRYPT_QUERY_INFO(string newAlgoName, int newBlockSize, int newMinKeySize, int newKeySize, int newMaxKeySize)
	{
		algoName = newAlgoName;
		blockSize = newBlockSize;
		minKeySize = newMinKeySize;
		keySize = newKeySize;
		maxKeySize = newMaxKeySize;
	}
}

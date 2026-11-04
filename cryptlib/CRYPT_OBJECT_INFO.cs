using System.Runtime.InteropServices;

namespace cryptlib;

[StructLayout(LayoutKind.Sequential)]
public class CRYPT_OBJECT_INFO
{
	public int objectType;

	public int cryptAlgo;

	public int cryptMode;

	public int hashAlgo;

	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
	public byte[] salt;

	public int saltSize;

	public CRYPT_OBJECT_INFO()
	{
		salt = new byte[64];
		saltSize = 64;
	}

	public CRYPT_OBJECT_INFO(int newObjectType, int newCryptAlgo, int newCryptMode, int newHashAlgo, byte[] newSalt)
	{
		objectType = newObjectType;
		cryptAlgo = newCryptAlgo;
		cryptMode = newCryptMode;
		hashAlgo = newHashAlgo;
	}
}

using System.Security.Cryptography;
using BitcoinNET.Utils.Objects;

namespace BitcoinNET.Utils
{
	public static class DoubleDigestSha256Helper
	{
		private static readonly DoubleDigest doubleDigest=new DoubleDigest(new SHA256Managed());

		/// <summary>
		/// See <see cref="DoubleDigest(byte[],int,int)"/>.
		/// </summary>
		public static byte[] DoubleDigest(byte[] input)
		{ return doubleDigest.CalculateDoubleDigest(input); }

		/// <summary>
		/// Calculates the SHA-256 hash of the given byte range, and then hashes the resulting hash again. This is standard procedure in BitCoin. The resulting hash is in big endian form.
		/// </summary>
		public static byte[] DoubleDigest(byte[] input,int offset,int length)
		{ return doubleDigest.CalculateDoubleDigest(input,offset,length); }

		/// <summary>
		/// Calculates SHA256(SHA256(byte range 1 + byte range 2)).
		/// </summary>
		public static byte[] DoubleDigestTwoBuffers(byte[] input1,int offset1,int length1,byte[] input2,int offset2,int length2)
		{ return doubleDigest.CalculateDoubleDigestTwoBuffers(input1,offset1,length1,input2,offset2,length2); }
	}
}

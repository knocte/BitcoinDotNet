using System;
using System.Security.Cryptography;

namespace BitcoinNET.Utils.Objects
{
	public class DoubleDigest
	{
		public readonly HashAlgorithm Algorithm;

		public DoubleDigest(HashAlgorithm algorithm)
		{ Algorithm=algorithm; }

		/// <summary>
		/// See <see cref="CalculateDoubleDigest(byte[],int,int)"/>.
		/// </summary>
		public byte[] CalculateDoubleDigest(byte[] input)
		{ return CalculateDoubleDigest(input,0,input.Length); }

		/// <summary>
		/// Calculates the hash of the given byte range, and then hashes the resulting hash again. This is standard procedure in BitCoin. The resulting hash is in big endian form.
		/// </summary>
		public byte[] CalculateDoubleDigest(byte[] input,int offset,int length)
		{ return Algorithm.ComputeHash(Algorithm.ComputeHash(input,offset,length)); }

		/// <summary>
		/// Calculates Hash(Hash(byte range 1 + byte range 2)).
		/// </summary>
		public byte[] CalculateDoubleDigestTwoBuffers(byte[] input1,int offset1,int length1,byte[] input2,int offset2,int length2)
		{
			byte[] buffer=new byte[length1+length2];
			Array.Copy(input1,offset1,buffer,0,length1);
			Array.Copy(input2,offset2,buffer,length1,length2);

			return CalculateDoubleDigest(buffer,0,buffer.Length);
		}
	}
}

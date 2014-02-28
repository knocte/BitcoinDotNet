using System;
using BitcoinNET.Utils.Extensions;
using Org.BouncyCastle.Math;

namespace BitcoinNET.Utils
{
	public static class MPIHelper
	{
		/// <summary>
		/// MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function.
		/// They consist of a 4 byte big endian length field, followed by the stated number of bytes representing the number in big endian format (with a sign bit).
		/// </summary>
		/// <param name="value"></param>
		/// <param name="includeLength">Indicates whether the 4 byte length field should be included</param>
		/// <returns></returns>
		public static byte[] Encode(BigInteger value,bool includeLength=true)
		{
			if(value.Equals(BigInteger.Zero))
			{
				if(!includeLength)
				{ return new byte[0]; }
				return new byte[] { 0x00,0x00,0x00,0x00 };
			}

			bool isNegative=value.CompareTo(BigInteger.Zero)<0;
			if(isNegative)
			{ value=value.Negate(); }

			byte[] array=value.ToByteArray();
			int length=array.Length;
			if((array[0] & 0x80)==0x80)
			{ length++; }

			if(includeLength)
			{
				byte[] result=new byte[length+4];
				Array.Copy(array,0,result,length-array.Length+3,array.Length);
				((uint)length).ToByteArrayBe(result);
				
				if(isNegative)
				{ result[4]|=0x80; }
				return result;
			}
			else
			{
				byte[] result;
				if(length!=array.Length)
				{
					result=new byte[length];
					Array.Copy(array,0,result,1,array.Length);
				}
				else
				{ result=array; }
				
				if(isNegative)
				{ result[0]|=0x80; }

				return result;
			}
		}

		/// <summary>
		/// MPI encoded numbers are produced by the OpenSSL BN_bn2mpi function.
		/// They consist of a 4 byte big endian length field, followed by the stated number of bytes representing the number in big endian format.
		/// </summary>
		public static BigInteger Decode(byte[] me,bool hasLength=true)
		{
			byte[] buffer;

			if(hasLength)
			{
				uint length=me.ReadUint32Be();
				buffer=new byte[length];

				Array.Copy(me,4,buffer,0,length);
			}
			else
			{ buffer=me; }

			if(buffer.Length==0)
			{ return BigInteger.Zero; }

			bool isNegative=(buffer[0] & 0x80)==0x80;
			if(isNegative)
			{ buffer[0]&=0x7f; }

			BigInteger result=new BigInteger(buffer);
			return isNegative?result.Negate():result;
		}
	}
}

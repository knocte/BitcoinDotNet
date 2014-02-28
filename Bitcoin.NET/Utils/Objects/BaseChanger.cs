using System;
using System.Linq;
using BitcoinNET.BitcoinObjects.Exceptions;
using Org.BouncyCastle.Math;

namespace BitcoinNET.Utils.Objects
{
	public class BaseChanger
	{
		public readonly string Alphabet;
		private readonly BigInteger Base;

		public BaseChanger(string alphabet)
		{
			Alphabet=alphabet;
			Base=BigInteger.ValueOf(Alphabet.Length);
		}

		public string Encode(byte[] input)
		{
			// Decode byte[] to BigInteger
			BigInteger intData=new BigInteger(1,input);

			// Encode BigInteger to Base string
			string result=string.Empty;
			while(intData.CompareTo(0)>0)
			{
				BigInteger[] divide=intData.DivideAndRemainder(Base);
				intData=divide[0];
				result=Alphabet[divide[1].IntValue]+result;
			}

			// Append `1` for each leading 0 byte
			for(int i=0;i<input.Length && input[i]==0;i++)
			{ result=Alphabet[0]+result; }
			return result;
		}

		/// <exception cref="AddressFormatException"/>
		public byte[] Decode(string input)
		{
			var bytes=DecodeToBigInteger(input).ToByteArray();
			// We may have got one more byte than we wanted, if the high bit of the next-to-last byte was not zero. This
			// is because BigIntegers are represented with twos-compliment notation, thus if the high bit of the last
			// byte happens to be 1 another 8 zero bits will be added to ensure the number parses as positive. Detect
			// that case here and chop it off.
			var stripSignByte=bytes.Length>1 && bytes[0]==0 && bytes[1]>=0x80;
			
			// Count the leading zeros, if any.
			var leadingZeros=0;
			for(int i=0;input[i]==Alphabet[0];i++)
			{ leadingZeros++; }

			// Now cut/pad correctly. Java 6 has a convenience for this, but Android can't use it.
			var tmp=new byte[bytes.Length-(stripSignByte?1:0)+leadingZeros];
			Array.Copy(bytes,stripSignByte?1:0,tmp,leadingZeros,tmp.Length-leadingZeros);
			return tmp;
		}

		/// <exception cref="AddressFormatException"/>
		public BigInteger DecodeToBigInteger(string input)
		{
			var bi=BigInteger.ValueOf(0);
			// Work backwards through the string.
			for(var i=input.Length-1;i>=0;i--)
			{
				var alphaIndex=Alphabet.IndexOf(input[i]);
				if(alphaIndex==-1)
				{ throw new AddressFormatException("Illegal character "+input[i]+" at "+i); }
				bi=bi.Add(BigInteger.ValueOf(alphaIndex).Multiply(Base.Pow(input.Length-1-i)));
			}
			return bi;
		}

		/// <summary>
		/// Uses the checksum in the last 4 bytes of the decoded data to verify the rest are correct. The checksum is removed from the returned data.
		/// </summary>
		/// <exception cref="AddressFormatException">If the input is not base 58 or the checksum does not validate.</exception>
		public byte[] DecodeChecked(string input)
		{
			var tmp=Decode(input);
			if(tmp.Length<4)
			{ throw new AddressFormatException("Input too short"); }

			var checksum=new byte[4];
			Array.Copy(tmp,tmp.Length-4,checksum,0,4);

			var bytes=new byte[tmp.Length-4];
			Array.Copy(tmp,0,bytes,0,tmp.Length - 4);

			tmp=DoubleDigestSha256Helper.DoubleDigest(bytes);
			var hash=new byte[4];
			Array.Copy(tmp,0,hash,0,4);
			if(!hash.SequenceEqual(checksum))
			{ throw new AddressFormatException("Checksum does not validate"); }
			return bytes;
		}
	}
}

using System;
using System.IO;
using Org.BouncyCastle.Math;

namespace BitcoinNET.Utils.Extensions
{
	public static class NumbersExtensions
	{
		public static byte[] ToByteArrayBe(this uint me)
		{
			byte[] buffer=new byte[4];
			me.ToByteArrayBe(buffer,0);
			return buffer;
		}
		public static void ToByteArrayBe(this uint me,byte[] buffer,int offset=0)
		{
			buffer[offset+0]=(byte)(me>>24);
			buffer[offset+1]=(byte)(me>>16);
			buffer[offset+2]=(byte)(me>>8);
			buffer[offset+3]=(byte)(me>>0);
		}

		public static byte[] ToByteArrayLe(this uint me)
		{
			byte[] buffer=new byte[4];
			me.ToByteArrayLe(buffer,0);
			return buffer;
		}
		public static void ToByteArrayLe(this uint me,byte[] buffer,int offset=0)
		{
			buffer[offset+0]=(byte)(me>>0);
			buffer[offset+1]=(byte)(me>>8);
			buffer[offset+2]=(byte)(me>>16);
			buffer[offset+3]=(byte)(me>>24);
		}


		public static byte[] ToByteArrayBe(this ulong me)
		{
			byte[] buffer=new byte[8];
			me.ToByteArrayBe(buffer,0);
			return buffer;
		}
		public static void ToByteArrayBe(this ulong me,byte[] buffer,int offset=0)
		{
			buffer[offset+0]=(byte)(me>>56);
			buffer[offset+1]=(byte)(me>>48);
			buffer[offset+2]=(byte)(me>>40);
			buffer[offset+3]=(byte)(me>>32);
			buffer[offset+4]=(byte)(me>>24);
			buffer[offset+5]=(byte)(me>>16);
			buffer[offset+6]=(byte)(me>>8);
			buffer[offset+7]=(byte)(me>>0);
		}

		public static byte[] ToByteArrayLe(this ulong me)
		{
			byte[] buffer=new byte[8];
			me.ToByteArrayLe(buffer,0);
			return buffer;
		}
		public static void ToByteArrayLe(this ulong me,byte[] buffer,int offset=0)
		{
			buffer[offset+0]=(byte)(me>>0);
			buffer[offset+1]=(byte)(me>>8);
			buffer[offset+2]=(byte)(me>>16);
			buffer[offset+3]=(byte)(me>>24);
			buffer[offset+4]=(byte)(me>>32);
			buffer[offset+5]=(byte)(me>>40);
			buffer[offset+6]=(byte)(me>>48);
			buffer[offset+7]=(byte)(me>>56);
		}


		public static byte[] ToByteArrayBe(this long me)
		{
			byte[] buffer=new byte[8];
			me.ToByteArrayBe(buffer,0);
			return buffer;
		}
		public static void ToByteArrayBe(this long me,byte[] buffer,int offset=0)
		{
			buffer[offset+0]=(byte)(me>>56);
			buffer[offset+1]=(byte)(me>>48);
			buffer[offset+2]=(byte)(me>>40);
			buffer[offset+3]=(byte)(me>>32);
			buffer[offset+4]=(byte)(me>>24);
			buffer[offset+5]=(byte)(me>>16);
			buffer[offset+6]=(byte)(me>>8);
			buffer[offset+7]=(byte)(me>>0);
		}

		public static byte[] ToByteArrayLe(this long me)
		{
			byte[] buffer=new byte[8];
			me.ToByteArrayLe(buffer,0);
			return buffer;
		}
		public static void ToByteArrayLe(this long me,byte[] buffer,int offset=0)
		{
			buffer[offset+0]=(byte)(me>>0);
			buffer[offset+1]=(byte)(me>>8);
			buffer[offset+2]=(byte)(me>>16);
			buffer[offset+3]=(byte)(me>>24);
			buffer[offset+4]=(byte)(me>>32);
			buffer[offset+5]=(byte)(me>>40);
			buffer[offset+6]=(byte)(me>>48);
			buffer[offset+7]=(byte)(me>>56);
		}


		/// <exception cref="IOException"/>
		public static void ToByteStreamBe(this uint me,Stream stream)
		{
			byte[] buffer=me.ToByteArrayBe();
			stream.Write(buffer,0,buffer.Length);
		}

		/// <exception cref="IOException"/>
		public static void ToByteStreamLe(this uint me,Stream stream)
		{
			byte[] buffer=me.ToByteArrayLe();
			stream.Write(buffer,0,buffer.Length);
		}

		/// <exception cref="IOException"/>
		public static void ToByteStreamBe(this ulong me,Stream stream)
		{
			var bytes=BitConverter.GetBytes(me);
			if(BitConverter.IsLittleEndian)
			{ Array.Reverse(bytes); }
			stream.Write(bytes,0,bytes.Length);
		}

		/// <exception cref="IOException"/>
		public static void ToByteStreamLe(this ulong me,Stream stream)
		{
			var bytes=BitConverter.GetBytes(me);
			if(!BitConverter.IsLittleEndian)
			{ Array.Reverse(bytes); }
			stream.Write(bytes,0,bytes.Length);
		}


		/// <summary>
		/// The representation of nBits uses another home-brew encoding, as a way to represent a large hash value in only 32 bits.
		/// </summary>
		/// <param name="me"></param>
		/// <returns></returns>
		public static BigInteger DecodeCompactBits(this uint me)
		{
			var size=(byte)(me>>24);
			var bytes=new byte[4+size];
			bytes[3]=size;
			
			if(size>=1)
			{ bytes[4]=(byte)(me>>16); }
			
			if(size>=2)
			{ bytes[5]=(byte)(me>>8); }

			if(size>=3)
			{ bytes[6]=(byte)(me>>0); }

			return bytes.DecodeMPI();
		}
	}
}

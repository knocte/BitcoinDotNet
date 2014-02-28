using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.Encoders;

namespace BitcoinNET.Utils.Extensions
{
	public static class ByteArrayExtensions
	{
		/// <summary>
		/// Returns the given byte array hex encoded.
		/// </summary>
		public static string BytesToHexString(this byte[] me)
		{
			//Correct?
			return Hex.ToHexString(me);

			//var buf=new StringBuilder(me.Length*2);
			//foreach(var b in me)
			//{
			//	var s=b.ToString("x");
			//	if(s.Length<2)
			//	{ buf.Append('0'); }
			//	buf.Append(s);
			//}
			//return buf.ToString();
		}

		/// <summary>
		/// Returns a copy of the given byte array in reverse order.
		/// </summary>
		public static byte[] ReverseBytes(this byte[] me)
		{
			// We could use the XOR trick here but it's easier to understand if we don't. If we find this is really a performance issue the matter can be revisited.
			var buf=new byte[me.Length];
			for(var i=0;i<me.Length;i++)
			{ buf[i]=me[me.Length-1-i]; }
			return buf;
		}

		public static byte[] Duplicate(this byte[] me,long? sourceIndex=null,long? length=null)
		{
			sourceIndex=sourceIndex??0;
			long maxLength=me.Length-sourceIndex.Value;
			length=Math.Min(length??(maxLength),maxLength);

			byte[] copy=new byte[length.Value];
			Array.Copy(me,sourceIndex.Value,copy,0,length.Value);
			return copy;
		}

		public static short ReadInt16(this byte[] me,int offset=0)
		{
			return (short)((me[offset+0]<<0) |
							(me[offset+1]<<8));
		}
		public static short ReadInt16Be(this byte[] me,int offset=0)
		{
			return (short)((me[offset+0]<<8) |
							(me[offset+1]<<0));
		}

		public static ushort ReadUint16(this byte[] me,int offset=0)
		{
			return (ushort)((me[offset+0]<<0) |
							(me[offset+1]<<8));
		}
		public static ushort ReadUint16Be(this byte[] me,int offset=0)
		{
			return (ushort)((me[offset+0]<<8) |
							(me[offset+1]<<0));
		}

		public static int ReadInt32(this byte[] me,int offset=0)
		{
			return (me[offset+0]<<0) |
                   (me[offset+1]<<8) |
                   (me[offset+2]<<16) |
                   (me[offset+3]<<24);
		}
		public static int ReadInt32Be(this byte[] me,int offset=0)
		{
			return (me[offset+0]<<24) |
                   (me[offset+1]<<16) |
                   (me[offset+2]<<8) |
                   (me[offset+3]<<0);
		}

		public static uint ReadUint32(this byte[] me,int offset=0)
		{
			return (((uint)me[offset+0])<<0) |
                   (((uint)me[offset+1])<<8) |
                   (((uint)me[offset+2])<<16) |
                   (((uint)me[offset+3])<<24);
		}
		public static uint ReadUint32Be(this byte[] me,int offset=0)
		{
			return (((uint)me[offset+0])<<24) |
                   (((uint)me[offset+1])<<16) |
                   (((uint)me[offset+2])<<8) |
                   (((uint)me[offset+3])<<0);
		}

		public static long ReadInt64(this byte[] me,int offset=0)
		{
			return (((long)me[offset+0])<<0) |
                   (((long)me[offset+1])<<8) |
                   (((long)me[offset+2])<<16) |
                   (((long)me[offset+3])<<24) |
                   (((long)me[offset+4])<<32) |
                   (((long)me[offset+5])<<40) |
                   (((long)me[offset+6])<<48) |
                   (((long)me[offset+7])<<56);
		}
		public static long ReadInt64Be(this byte[] me,int offset=0)
		{
			return (((long)me[offset+0])<<56) |
                   (((long)me[offset+1])<<48) |
                   (((long)me[offset+2])<<40) |
                   (((long)me[offset+3])<<32) |
                   (((long)me[offset+4])<<24) |
                   (((long)me[offset+5])<<16) |
                   (((long)me[offset+6])<<8) |
                   (((long)me[offset+7])<<0);
		}

		public static ulong ReadUint64(this byte[] me,int offset=0)
		{
			return (((ulong)me[offset+0])<<0) |
                   (((ulong)me[offset+1])<<8) |
                   (((ulong)me[offset+2])<<16) |
                   (((ulong)me[offset+3])<<24) |
                   (((ulong)me[offset+4])<<32) |
                   (((ulong)me[offset+5])<<40) |
                   (((ulong)me[offset+6])<<48) |
                   (((ulong)me[offset+7])<<56);
		}
		public static ulong ReadUint64Be(this byte[] me,int offset=0)
		{
			return (((ulong)me[offset+0])<<56) |
                   (((ulong)me[offset+1])<<48) |
                   (((ulong)me[offset+2])<<40) |
                   (((ulong)me[offset+3])<<32) |
                   (((ulong)me[offset+4])<<24) |
                   (((ulong)me[offset+5])<<16) |
                   (((ulong)me[offset+6])<<8) |
                   (((ulong)me[offset+7])<<0);
		}



		/// <summary>
		/// Calculates RIPEMD160(SHA256(input)). This is used in Address calculations.
		/// </summary>
		public static byte[] Sha256Hash160(this byte[] me)
		{
			byte[] sha256=new SHA256Managed().ComputeHash(me);
			RipeMD160Digest digest=new RipeMD160Digest();
			digest.BlockUpdate(sha256,0,sha256.Length);
			
			byte[] result=new byte[20];
			digest.DoFinal(result,0);
			return result;
		}
	}
}

using BitcoinNET.Utils.Extensions;

namespace BitcoinNET.Utils.Objects
{
	public class VarInt
	{
		public readonly ulong Value;

		public VarInt(ulong value)
		{ Value=value; }

		// BitCoin has its own variant format, known in the C++ source as "compact size".
		public VarInt(byte[] buf,int offset)
		{
			byte firstByte=buf[offset];

			if(firstByte<253)
			{ Value=firstByte; }	// 8 bits
			else if(firstByte==253)
			{ Value=(ushort)(buf[offset+1] | (buf[offset+2]<<8)); }	// 16 bits
			else if(firstByte==254)
			{ Value=buf.ReadUint32(offset+1); }	// 32 bits
			else
			{ Value=buf.ReadUint32(offset+1) | (((ulong)buf.ReadUint32(offset+5))<<32); }	// 64 bits
		}

		public int SizeInBytes { get { return SizeInBytesOf(Value); } }

		public byte[] Encode()
		{ return EncodeBe(); }
		public byte[] EncodeBe()
		{
			if(Value<253)
			{ return new[] { (byte)Value }; }

			if(Value<=ushort.MaxValue)
			{ return new[] { (byte)253,(byte)Value,(byte)(Value>>8) }; }

			if(Value<=uint.MaxValue)
			{
				byte[] bytes=new byte[5];
				bytes[0]=254;
				((uint)Value).ToByteArrayLe(bytes,1);
				return bytes;
			}
			else
			{
				byte[] bytes=new byte[9];
				bytes[0]=255;
				Value.ToByteArrayLe(bytes,1);
				return bytes;
			}
		}

		public static int SizeInBytesOf(ulong value)
		{
			// Java doesn't have the actual value of MAX_INT, as all types in Java are signed.
			if(value<253)
			{ return 1; }
			if(value<=ushort.MaxValue)
			{ return 3; } // 1 marker + 2 data bytes
			if(value<=uint.MaxValue)
			{ return 5; } // 1 marker + 4 data bytes
			return 9; // 1 marker + 8 data bytes
		}
	}
}

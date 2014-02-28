using System;
using System.Diagnostics;
using System.Linq;
using BitcoinNET.BitcoinObjects.Exceptions;
using BitcoinNET.Utils;

namespace BitcoinNET.BitcoinObjects
{
	/// <summary>
	/// In Bitcoin the following format is often used to represent some type of key:
	/// <pre>[one version byte] [data bytes] [4 checksum bytes]</pre>
	/// and the result is then Base58 encoded. This format is used for addresses, and private keys exported using the "dumpprivkey" command.
	/// </summary>
	public class VersionedChecksummedBytes
	{
		/// <summary>
		/// Returns the "version" or "header" byte: the first byte of the data.
		/// This is used to disambiguate what the contents apply to, for example, which network the key or address is valid on.
		/// </summary>
		/// <returns>A positive number between 0 and 255.</returns>
		public int Version { get; private set; }
		protected byte[] Bytes { get; private set; }

		/// <exception cref="AddressFormatException"/>
		protected VersionedChecksummedBytes(string encoded)
		{
			var tmp=Base58Helper.DecodeChecked(encoded);
			Version=tmp[0];
			Bytes=new byte[tmp.Length-1];
			Array.Copy(tmp,1,Bytes,0,tmp.Length-1);
		}

		protected VersionedChecksummedBytes(int version,byte[] bytes)
		{
			Debug.Assert(version < 256 && version >= 0);
			Version=version;
			Bytes=bytes;
		}

		public override string ToString()
		{
			// A stringified buffer is:
			//   1 byte version + data bytes hash + 4 bytes check code (itself a truncated hash)
			var addressBytes=new byte[1+Bytes.Length+4];
			addressBytes[0]=(byte)Version;
			Array.Copy(Bytes,0,addressBytes,1,Bytes.Length);
			var check=Utils.DoubleDigest(addressBytes,0,Bytes.Length+1);
			Array.Copy(check,0,addressBytes,Bytes.Length+1,4);
			return Base58Helper.Encode(addressBytes);
		}

		public override int GetHashCode()
		{ return Bytes!=null?Bytes.Aggregate(1,(_current,_element) => 31*_current+_element):0; }

		public override bool Equals(object o)
		{
			if(!(o is VersionedChecksummedBytes))
			{ return false; }
			return ((VersionedChecksummedBytes)o).Bytes.SequenceEqual(Bytes);
		}
	}
}

using System;
using System.Linq;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;

namespace BitcoinNET.Utils.Objects
{
	/// <summary>
	/// A Sha256Hash just wraps a byte[] so that equals and hashcode work correctly, allowing it to be used as keys in a
	/// map. It also checks that the length is correct and provides a bit more type safety.
	/// </summary>
	[Serializable]
	public class Sha256Hash
	{
		public static readonly Sha256Hash ZeroHash=new Sha256Hash(new byte[32]);

		public readonly byte[] Bytes;

		/// <summary>
		/// Creates a Sha256Hash by decoding the given hex string. It must be 64 characters long.
		/// </summary>
		public Sha256Hash(string hash):this(Hex.Decode(hash))
		{ }


		/// <summary>
		/// Creates a Sha256Hash by wrapping the given byte array. It must be 32 bytes long.
		/// </summary>
		public Sha256Hash(byte[] bytes)
		{ Bytes=bytes; }

		/// <summary>
		/// Returns the bytes interpreted as a positive integer.
		/// </summary>
		public BigInteger ToBigInteger()
		{ return new BigInteger(1,Bytes); }

		public Sha256Hash Duplicate()
		{ return new Sha256Hash(Bytes); }


		/// <summary>
		/// Returns true if the hashes are equal.
		/// </summary>
		public override bool Equals(object other)
		{
			if(other==null)
			{ return false; }

			if(!(other is Sha256Hash))
			{ return false; }
			return  ReferenceEquals(this,other) || Bytes.SequenceEqual(((Sha256Hash)other).Bytes);
		}

		/// <summary>
		/// Hash code of the byte array as calculated by <see cref="object.GetHashCode"/>. Note the difference between a SHA256
		/// secure bytes and the type of quick/dirty bytes used by the Java hashCode method which is designed for use in bytes tables.
		/// </summary>
		public override int GetHashCode()
		{
			if(Bytes!=null)
			{ return Bytes.Aggregate(1,(_current,_element) => 31*_current+_element); }
			return 0;
		}

		public override string ToString()
		{
			//return Bytes.ToHexString();

			//Correct?
			return Hex.ToHexString(Bytes);
		}
	}
}

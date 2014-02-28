using BitcoinNET.BitcoinObjects.Exceptions;
using BitcoinNET.Utils.Objects;
using Org.BouncyCastle.Math;

namespace BitcoinNET.Utils
{
	/// <summary>
	/// A custom form of base58 is used to encode BitCoin addresses. Note that this is not the same base58 as used by Flickr, which you may see reference to around the internet.
	/// </summary>
	/// <remarks>
	/// Satoshi says: why base-58 instead of standard base-64 encoding?<p/>
	/// <ul>
	///   <li>Don't want 0OIl characters that look the same in some fonts and could be used to create visually identical looking account numbers.</li>
	///   <li>A string with non-alphanumeric characters is not as easily accepted as an account number.</li>
	///   <li>E-mail usually won't line-break if there's no punctuation to break at.</li>
	///   <li>Double clicking selects the whole number as one word if it's all alphanumeric.</li>
	/// </ul>
	/// </remarks>
	public static class Base58Helper
	{
		private static readonly BaseChanger baseChanger=new BaseChanger("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");

		public static string Encode(byte[] input)
		{ return baseChanger.Encode(input); }

		/// <exception cref="AddressFormatException"/>
		public static byte[] Decode(string input)
		{ return baseChanger.Decode(input); }

		/// <exception cref="AddressFormatException"/>
		public static BigInteger DecodeToBigInteger(string input)
		{ return baseChanger.DecodeToBigInteger(input); }

		/// <summary>
		/// Uses the checksum in the last 4 bytes of the decoded data to verify the rest are correct. The checksum is
		/// removed from the returned data.
		/// </summary>
		/// <exception cref="AddressFormatException">If the input is not base 58 or the checksum does not validate.</exception>
		public static byte[] DecodeChecked(string input)
		{ return baseChanger.DecodeChecked(input); }
	}
}

using System;

namespace BitcoinNET.BitcoinObjects.Exceptions
{
	public class AddressFormatException:Exception
	{
		public AddressFormatException(string message):base(message)
		{ }
		public AddressFormatException(string message,Exception innerException):base(message,innerException)
		{ }
	}
}

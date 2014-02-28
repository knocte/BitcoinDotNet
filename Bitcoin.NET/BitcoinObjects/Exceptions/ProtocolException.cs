using System;

namespace BitcoinNET.BitcoinObjects.Exceptions
{
	public class ProtocolException:Exception
	{
		public ProtocolException()
		{ }
		public ProtocolException(string message):base(message)
		{ }
		public ProtocolException(Exception innerException):base(innerException.Message,innerException)
		{ }
		public ProtocolException(string message,Exception innerException):base(message,innerException)
		{ }
	}
}

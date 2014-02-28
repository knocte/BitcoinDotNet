using System;

namespace BitcoinNET.BitcoinObjects.Exceptions
{
	public class ScriptException:Exception
	{
		public ScriptException()
		{ }
		public ScriptException(string message):base(message)
		{ }
		public ScriptException(Exception innerException):base(innerException.Message,innerException)
		{ }
		public ScriptException(string message,Exception innerException):base(message,innerException)
		{ }
	}
}

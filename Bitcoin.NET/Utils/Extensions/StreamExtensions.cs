using System.IO;

namespace BitcoinNET.Utils.Extensions
{
	public static class StreamExtensions
	{
		public static void Write(this Stream me,byte element)
		{ me.Write(new[] { element },0,1); }
		public static void Write(this Stream me,byte[] buffer)
		{ me.Write(buffer,0,buffer.Length); }
	}
}

using System;

namespace BitcoinNET.Utils
{
	public static class UnixTimeHelper
	{
		private static readonly DateTime unixEpoch=new DateTime(1970,1,1,0,0,0,DateTimeKind.Utc);

		public static uint ToUnixTime(DateTime dateTime)
		{ return (uint)(dateTime.ToUniversalTime()-unixEpoch).TotalSeconds; }

		public static DateTime FromUnixTime(ulong unixTime)
		{ return unixEpoch.AddSeconds(unixTime); }
	}
}

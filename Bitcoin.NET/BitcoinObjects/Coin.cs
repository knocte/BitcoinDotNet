using Org.BouncyCastle.Math;

namespace BitcoinNET.BitcoinObjects
{
	public class Coin
	{
		/// <summary>
		/// How many "nanocoins" there are in a Bitcoin.
		/// A nanocoin is the smallest unit that can be transferred using Bitcoin.
		/// The term nanocoin is very misleading, though, because there are only 100 million of them in a coin (whereas one would expect 1 billion).
		/// </summary>
		public const long NanoCoinsInCoin=100000000;
		private static readonly BigInteger nanoCoinsInCoinBigInteger=BigInteger.ValueOf(NanoCoinsInCoin);
		private static readonly BigInteger nanoCoinsInCoinCentBigInteger=BigInteger.ValueOf(NanoCoinsInCoin/100);


		public readonly BigInteger Nanocoins;
		public decimal Coins { get { return (decimal)Nanocoins.LongValue/NanoCoinsInCoin; } }

		private Coin(long nanocoins)
		{ Nanocoins=BigInteger.ValueOf(nanocoins); }
		private Coin(BigInteger nanocoins)
		{ Nanocoins=nanocoins; }


		public static Coin FromCoins(double coins)
		{ return new Coin((long)(coins*NanoCoinsInCoin)); }
		public static Coin FromCoins(decimal coins)
		{ return new Coin((long)(coins*NanoCoinsInCoin)); }
		public static Coin FromCoins(long coins)
		{ return new Coin(BigInteger.ValueOf(coins).Multiply(nanoCoinsInCoinBigInteger)); }
		public static Coin FromCoins(long coins,short cents)
		{ return new Coin(BigInteger.ValueOf(coins).Multiply(nanoCoinsInCoinBigInteger).Add(BigInteger.ValueOf(cents).Multiply(nanoCoinsInCoinCentBigInteger))); }
		public static Coin FromCoins(BigInteger coins)
		{ return new Coin(coins.Multiply(nanoCoinsInCoinBigInteger)); }

		public static Coin FromNanoCoins(long nanocoins)
		{ return new Coin(nanocoins); }
		public static Coin FromNanoCoins(BigInteger nanocoins)
		{ return new Coin(nanocoins); }
	}
}

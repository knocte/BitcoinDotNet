using System;

namespace BitcoinNET.BitcoinObjects.BlockStore.Exceptions
{
	/// <summary>
	/// Thrown when something goes wrong with storing a block.
	/// </summary>
	/// <remarks>
	/// Examples: out of disk space.
	/// </remarks>
	public class BlockStoreException:Exception
	{
		public BlockStoreException()
		{ }
		public BlockStoreException(string message):base(message)
		{ }
		public BlockStoreException(Exception innerException):base(innerException.Message,innerException)
		{ }
	}
}

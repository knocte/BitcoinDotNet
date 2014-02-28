using System;
using BitcoinNET.BitcoinObjects.BlockStore.Exceptions;
using BitcoinNET.BitcoinObjects.Parameters.Abstractions;
using BitcoinNET.Utils.Objects;

namespace BitcoinNET.BitcoinObjects.BlockStore.Abstractions
{
	/// <summary>
	/// An implementor of BlockStore saves StoredBlock objects to disk. Different implementations store them in
	/// different ways. An in-memory implementation (MemoryBlockStore) exists for unit testing but real apps will want to
	/// use implementations that save to disk.
	/// </summary>
	/// <remarks>
	/// A BlockStore is a map of hashes to StoredBlock. The hash is the double digest of the BitCoin serialization
	/// of the block header, <b>not</b> the header with the extra data as well.
	/// BlockStores are thread safe.
	/// </remarks>
	public abstract class ABlockStore:IDisposable
	{
		/// <summary>
		/// The <see cref="StoredBlock"/> that represents the top of the chain of greatest total work.
		/// </summary>
		public StoredBlock ChainHead { get; set; }

		protected ABlockStore(NetworkParameters parameters)
		{
			// Insert the genesis block.
			var genesisHeader=parameters.GenesisBlock.CloneAsHeader();
			StoredBlock storedGenesis=new StoredBlock(genesisHeader,genesisHeader.GetWork(),0);
			
			Put(storedGenesis);
			ChainHead=storedGenesis;
		}

		/// <summary>
		/// Returns the StoredBlock given a hash. The returned values block.getHash() method will be equal to the
		/// parameter. If no such block is found, returns null.
		/// </summary>
		/// <exception cref="BlockStoreException"/>
		public abstract StoredBlock Get(Sha256Hash hash);

		/// <summary>
		/// Saves the given block header+extra data. The key isn't specified explicitly as it can be calculated from the
		/// StoredBlock directly. Can throw if there is a problem with the underlying storage layer such as running out of
		/// disk space.
		/// </summary>
		/// <exception cref="BlockStoreException"/>
		public abstract void Put(StoredBlock block);

		public abstract void Dispose();
	}
}

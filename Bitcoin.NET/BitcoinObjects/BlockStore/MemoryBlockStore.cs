using System.Collections.Generic;
using BitcoinNET.BitcoinObjects.BlockStore.Abstractions;
using BitcoinNET.BitcoinObjects.Parameters.Abstractions;
using BitcoinNET.Utils.Objects;

namespace BitcoinNET.BitcoinObjects.BlockStore
{
	public class MemoryStore:ABlockStore
	{
		private readonly ReaderWriterLockDisposable locker;
		private readonly IDictionary<string,StoredBlock> store;

		public MemoryStore(NetworkParameters parameters):base(parameters)
		{
			locker=new ReaderWriterLockDisposable();
			using(locker.AcquireWriterLock())
			{ store=new Dictionary<string,StoredBlock>(); }
		}

		public override StoredBlock Get(Sha256Hash hash)
		{
			using(locker.AcquireReaderLock())
			{
				StoredBlock block;
				if(store.TryGetValue(hash.ToString(),out block))
				{ return block; }
				return null;
			}
		}

		public override void Put(StoredBlock block)
		{
			using(locker.AcquireWriterLock())
			{ store[block.Header.Hash.ToString()]=block; }
		}

		public override void Dispose()
		{
			throw new System.NotImplementedException();
		}
	}
}

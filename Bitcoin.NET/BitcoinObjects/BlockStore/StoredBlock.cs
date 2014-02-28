using System;
using System.Security;
using BitcoinNET.BitcoinObjects.BlockStore.Abstractions;
using BitcoinNET.BitcoinObjects.BlockStore.Exceptions;
using Org.BouncyCastle.Math;

namespace BitcoinNET.BitcoinObjects.BlockStore
{
	/// <summary>
	/// Wraps a <see cref="Block"/> object with extra data that can be derived from the block chain but is slow or inconvenient to
	/// calculate. By storing it alongside the block header we reduce the amount of work required significantly.
	/// Recalculation is slow because the fields are cumulative - to find the chainWork you have to iterate over every
	/// block in the chain back to the genesis block, which involves lots of seeking/loading etc. So we just keep a
	/// running total: it's a disk space vs CPU/IO tradeoff.
	/// </summary>
	/// <remarks>
	/// StoredBlocks are put inside a <see cref="ABlockStore"/> which saves them to memory or disk.
	/// </remarks>
	[Serializable]
	public class StoredBlock:Block
	{
		/// <summary>
		/// The block header this object wraps. The referenced block object must not have any transactions in it.
		/// </summary>
		public readonly Block Header;

		/// <summary>
		/// The total sum of work done in this block, and all the blocks below it in the chain. Work is a measure of how
		/// many tries are needed to solve a block. If the target is set to cover 10% of the total hash value space,
		/// then the work represented by a block is 10.
		/// </summary>
		public readonly BigInteger ChainWork;

		/// <summary>
		/// Position in the chain for this block. The genesis block has a height of zero.
		/// </summary>
		public readonly uint Height;

		public StoredBlock(Block header,BigInteger chainWork,uint height)
		{
			Header=header;
			ChainWork=chainWork;
			Height=height;
		}

		/// <summary>
		/// Returns true if this objects chainWork is higher than the others.
		/// </summary>
		public bool MoreWorkThan(StoredBlock other)
		{
			return ChainWork.CompareTo(other.ChainWork)>0;
		}

		/// <summary>
		/// Creates a new StoredBlock, calculating the additional fields by adding to the values in this block.
		/// </summary>
		/// <exception cref="VerificationException"/>
		public StoredBlock Build(Block block)
		{
			// Stored blocks track total work done in this chain, because the canonical chain is the one that represents
			// the largest amount of work done not the tallest.
			return new StoredBlock(block.CloneAsHeader(),ChainWork.Add(block.GetWork()),Height+1);
		}

		/// <summary>
		/// Given a block store, looks up the previous block in this chain. Convenience method for doing <tt>store.get(storedBlock.Header.PreviousBlockHash)</tt>.
		/// </summary>
		/// <returns>The previous block in the chain or null if it was not found in the store.</returns>
		/// <exception cref="BlockStoreException"/>
		public StoredBlock GetPrevious(ABlockStore store)
		{ return store.Get(Header.PreviousBlockHash); }

		public override string ToString()
		{ return string.Format("Block {0} at height {1}: {2}",Header.HashAsString,Height,Header); }

		public override bool Equals(object other)
		{
			if(other==null)
			{ return false; }

			if(!(other is StoredBlock))
			{ return false; }

			StoredBlock otherStronglyTyped=(StoredBlock)other;
			return ReferenceEquals(this,other) || (otherStronglyTyped.Header.Equals(Header) && otherStronglyTyped.ChainWork.Equals(ChainWork) && otherStronglyTyped.Height==Height);
		}

		public override int GetHashCode()
		{
			// A better hashCode is possible, but this works for now.
			return Header.GetHashCode()^ChainWork.GetHashCode()^(int)Height;
		}
	}
}

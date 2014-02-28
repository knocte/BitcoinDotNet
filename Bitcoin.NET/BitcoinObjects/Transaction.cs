﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using BitcoinNET.BitcoinObjects.Abstractions;
using BitcoinNET.BitcoinObjects.BlockStore;
using BitcoinNET.BitcoinObjects.Parameters.Abstractions;
using BitcoinNET.Utils;
using BitcoinNET.Utils.Extensions;
using BitcoinNET.Utils.Objects;
using Org.BouncyCastle.Math;

namespace BitcoinNET.BitcoinObjects
{
	/// <summary>
    /// A transaction represents the movement of coins from some addresses to some other addresses. It can also represent
    /// the minting of new coins. A Transaction object corresponds to the equivalent in the BitCoin C++ implementation.
    /// </summary>
    /// <remarks>
    /// It implements TWO serialization protocols - the Bitcoin proprietary format which is identical to the C++
    /// implementation and is used for reading/writing transactions to the wire and for hashing. It also implements Java
    /// serialization which is used for the wallet. This allows us to easily add extra fields used for our own accounting
    /// or UI purposes.
    /// </remarks>
	[Serializable]
	public class Transaction:AMessage
	{
		// Threshold for lockTime: below this value it is interpreted as block number, otherwise as timestamp.
		public const int LocktimeThreshold=500000000; // Tue Nov  5 00:53:20 1985 UTC

		// These are serialized in both bitcoin and java serialization.
		private long version;
		private List<TransactionInput> inputs;
		private List<TransactionOutput> outputs;

		private long lockTime;

		// This is either the time the transaction was broadcast as measured from the local clock, or the time from the
		// block in which it was included. Note that this can be changed by re-orgs so the wallet may update this field.
		// Old serialized transactions don't have this field, thus null is valid. It is used for returning an ordered
		// list of transactions from a wallet, which is helpful for presenting to users.
		private DateTime updatedAt;

		// This is an in memory helper only.
		[NonSerialized]private Sha256Hash hash;
		public override Sha256Hash Hash
		{
			get
			{
				if(hash==null)
				{ hash=new Sha256Hash(DoubleDigestSha256Helper.DoubleDigest(BitcoinSerialize()).ReverseBytes()); }
				return hash;
			}
		}	//Returns the hash of the block (which for a valid, solved block should be below the target). Big endian.

		private string hashString;
		public string HashString
		{
			get
			{ return hashString??(hashString=Hash.ToString()); }
		}	//Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on the block explorer. If you call this on block 1 in the production chain you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".

		

		///**
		// * Convenience wrapper around getConfidence().getConfidenceType()
		// * @return true if this transaction hasn't been seen in any block yet.
		// */
		//public bool IsPending
		//{ get { return getConfidence().getConfidenceType()==TransactionConfidence.ConfidenceType.NOT_SEEN_IN_CHAIN; } }
		
		/**
		 * Returns true if every output is marked as spent.
		 */
		public bool IsEveryOutputSpent
		{
			get
			{
				EnsureParsed();
				foreach(TransactionOutput output in outputs)
				{
					if(output.IsAvailableForSpending)
					{ return false; }
				}
				return true;
			}
		}

		

		/**
		 * A coinbase transaction is one that creates a new coin. They are the first transaction in each block and their
		 * value is determined by a formula that all implementations of Bitcoin share. In 2011 the value of a coinbase
		 * transaction is 50 coins, but in future it will be less. A coinbase transaction is defined not only by its
		 * position in a block but by the data in the inputs.
		 */
		public bool IsCoinBase
		{
			get
			{
				EnsureParsed();
				return inputs.Count== 1 && inputs[0].IsCoinBase;
			}
			
		}

		///**
		// * A transaction is mature if it is either a building coinbase tx that is as deep or deeper than the required coinbase depth, or a non-coinbase tx.
		// */
		//public bool IsMature
		//{
		//	get
		//	{
		//		if(!IsCoinBase)
		//		{ return true; }
				
		//		if(Confidence.ConfidenceType!=ConfidenceType.BUILDING)
		//		{ return false; }
				
		//		return Confidence.GetDepthInBlocks()>=Parameters.GetSpendableCoinbaseDepth();
		//	}
		//}

		///**
		// * Returns true if every output owned by the given wallet is spent.
		// */
		//public bool IsEveryOwnedOutputSpent(Wallet wallet) {
		//	maybeParse();
		//	for (TransactionOutput output : outputs) {
		//		if (output.isAvailableForSpending() && output.isMine(wallet))
		//			return false;
		//	}
		//	return true;
		//}


		// Data about how confirmed this tx is. Serialized, may be null. 
		//private TransactionConfidence confidence;

		// This records which blocks the transaction has been included in. For most transactions this set will have a
		// single member. In the case of a chain split a transaction may appear in multiple blocks but only one of them
		// is part of the best chain. It's not valid to have an identical transaction appear in two blocks in the same chain
		// but this invariant is expensive to check, so it's not directly enforced anywhere.
		//
		// If this transaction is not stored in the wallet, appearsInHashes is null.
		private HashSet<Sha256Hash> appearsInHashes;
    
		// Transactions can be encoded in a way that will use more bytes than is optimal
		// (due to VarInts having multiple encodings)
		// MAX_BLOCK_SIZE must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
		// of the size of the ideal encoding in addition to the actual message size (which Message needs) so that Blocks
		// can properly keep track of optimal encoded size
		[NonSerialized]private int optimalEncodingMessageSize;

		public Transaction(NetworkParameters parameters):this(parameters,1,null)
		{ }
		public Transaction(NetworkParameters parameters,int version,Sha256Hash hash):base(parameters)
		{
			this.version=version & ((1L<<32)-1); // this field is unsigned - remove any sign extension
			inputs=new List<TransactionInput>();
			outputs=new List<TransactionOutput>();
			this.hash=hash;

			// We don't initialize appearsIn deliberately as it's only useful for transactions stored in the wallet.
			Length=8; //8 for std fields
		}

		/**
		 * Creates a transaction from the given serialized bytes, eg, from a block or a tx network message.
		 *///throws ProtocolException
		public Transaction(NetworkParameters parameters,byte[] payload):this(parameters,payload,0)
		{ }

		/**
		 * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
		 */
		public Transaction(NetworkParameters parameters,byte[] payload,int offset):base(parameters,payload,offset)
		{ }

		/**
		 * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
		 * throws ProtocolException
		 */
		public Transaction(NetworkParameters parameters,byte[] msg,AMessage parent,bool parseLazy,bool parseRetain,int length):this(parameters,msg,0,parent,parseLazy,parseRetain,length)
		{ }

		/**
		 * Creates a transaction by reading payload starting from offset bytes in. Length of a transaction is fixed.
		 * @param params NetworkParameters object.
		 * @param msg Bitcoin protocol formatted byte array containing message content.
		 * @param offset The location of the first msg byte within the array.
		 * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
		 * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
		 * If true and the backing byte array is invalidated due to modification of a field then 
		 * the cached bytes may be repopulated and retained if the message is serialized again in the future.
		 * @param length The length of message if known.  Usually this is provided when deserializing of the wire
		 * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
		 * @throws ProtocolException
		 * 
		 * throws ProtocolException
		 */
		public Transaction(NetworkParameters parameters,byte[] msg,int offset,AMessage parent,bool parseLazy,bool parseRetain,int length):base(parameters,msg,offset,parent,parseLazy,parseRetain,length)
		{ }

		

		///**
		// * Calculates the sum of the outputs that are sending coins to a key in the wallet. The flag controls whether to
		// * include spent outputs or not.
		// */
		//BigInteger getValueSentToMe(Wallet wallet,bool includeSpent)
		//{
		//	EnsureParsed();
		//	// This is tested in WalletTest.
		//	BigInteger v = BigInteger.ZERO;
		//	for (TransactionOutput o : outputs) {
		//		if (!o.isMine(wallet)) continue;
		//		if (!includeSpent && !o.isAvailableForSpending()) continue;
		//		v = v.add(o.getValue());
		//	}
		//	return v;
		//}
    
		///*
		// * If isSpent - check that all my outputs spent, otherwise check that there at least
		// * one unspent.
		// */
		//boolean isConsistent(Wallet wallet, boolean isSpent) {
		//	boolean isActuallySpent = true;
		//	for (TransactionOutput o : outputs) {
		//		if (o.isAvailableForSpending()) {
		//			if (o.isMine(wallet)) isActuallySpent = false;
		//			if (o.getSpentBy() != null) {
		//				log.error("isAvailableForSpending != spentBy");
		//				return false;
		//			}
		//		} else {
		//			if (o.getSpentBy() == null) {
		//				log.error("isAvailableForSpending != spentBy");
		//				return false;
		//			}
		//		}
		//	}
		//	return isActuallySpent == isSpent;
		//}

		///**
		// * Calculates the sum of the outputs that are sending coins to a key in the wallet.
		// */
		//public BigInteger getValueSentToMe(Wallet wallet) {
		//	return getValueSentToMe(wallet, true);
		//}

		///**
		// * Returns a set of blocks which contain the transaction, or null if this transaction doesn't have that data
		// * because it's not stored in the wallet or because it has never appeared in a block.
		// */
		//public Collection<Sha256Hash> getAppearsInHashes() {
		//	return appearsInHashes;
		//}

		/**
		 * <p>Puts the given block in the internal serializable set of blocks in which this transaction appears. This is
		 * used by the wallet to ensure transactions that appear on side chains are recorded properly even though the
		 * block stores do not save the transaction data at all.</p>
		 *
		 * <p>If there is a re-org this will be called once for each block that was previously seen, to update which block
		 * is the best chain. The best chain block is guaranteed to be called last. So this must be idempotent.</p>
		 *
		 * <p>Sets updatedAt to be the earliest valid block time where this tx was seen.</p>
		 * 
		 * @param block     The {@link StoredBlock} in which the transaction has appeared.
		 * @param bestChain whether to set the updatedAt timestamp from the block header (only if not already set)
		 */
		public void setBlockAppearance(StoredBlock block,bool bestChain)
		{
			long blockTime=block.GetHeader().TimeSeconds;
			if (bestChain && (updatedAt == null || updatedAt.getTime() == 0 || updatedAt.getTime() > blockTime)) {
				updatedAt = new Date(blockTime);
			}

			addBlockAppearance(block.GetHeader().getHash());

			if(bestChain)
			{
				// This can cause event listeners on TransactionConfidence to run. After these lines complete, the wallets
				// state may have changed!
				TransactionConfidence transactionConfidence = getConfidence();
				transactionConfidence.setAppearedAtChainHeight(block.getHeight());

				// Reset the confidence block depth.
				transactionConfidence.setDepthInBlocks(1);

				// Reset the work done.
				transactionConfidence.setWorkDone(block.getHeader().getWork());

				// The transaction is now on the best chain.
				transactionConfidence.setConfidenceType(ConfidenceType.BUILDING);
			}
		}

		public void addBlockAppearance(Sha256Hash blockHash)
		{
			if(appearsInHashes==null)
			{ appearsInHashes=new HashSet<Sha256Hash>(); }
			appearsInHashes.Add(blockHash);
		}

		///** Called by the wallet once a re-org means we don't appear in the best chain anymore. */
		//void notifyNotOnBestChain()
		//{
		//	TransactionConfidence transactionConfidence = getConfidence();
		//	transactionConfidence.setConfidenceType(TransactionConfidence.ConfidenceType.NOT_IN_BEST_CHAIN);
		//	transactionConfidence.setDepthInBlocks(0);
		//	transactionConfidence.setWorkDone(BigInteger.ZERO);
		//}

		///**
		// * Calculates the sum of the inputs that are spending coins with keys in the wallet. This requires the
		// * transactions sending coins to those keys to be in the wallet. This method will not attempt to download the
		// * blocks containing the input transactions if the key is in the wallet but the transactions are not.
		// *
		// * @return sum in nanocoins.
		// */
		//public BigInteger getValueSentFromMe(Wallet wallet) throws ScriptException {
		//	maybeParse();
		//	// This is tested in WalletTest.
		//	BigInteger v = BigInteger.ZERO;
		//	for (TransactionInput input : inputs) {
		//		// This input is taking value from a transaction in our wallet. To discover the value,
		//		// we must find the connected transaction.
		//		TransactionOutput connected = input.getConnectedOutput(wallet.unspent);
		//		if (connected == null)
		//			connected = input.getConnectedOutput(wallet.spent);
		//		if (connected == null)
		//			connected = input.getConnectedOutput(wallet.pending);
		//		if (connected == null)
		//			continue;
		//		// The connected output may be the change to the sender of a previous input sent to this wallet. In this
		//		// case we ignore it.
		//		if (!connected.isMine(wallet))
		//			continue;
		//		v = v.add(connected.getValue());
		//	}
		//	return v;
		//}

		///**
		// * Returns the difference of {@link Transaction#getValueSentFromMe(Wallet)} and {@link Transaction#getValueSentToMe(Wallet)}.
		// */
		//public BigInteger getValue(Wallet wallet) throws ScriptException {
		//	return getValueSentToMe(wallet).subtract(getValueSentFromMe(wallet));
		//}

		public bool disconnectInputs()
		{
			EnsureParsed();
			
			bool disconnected=false;
			foreach(TransactionInput input in inputs)
			{ disconnected|=input.Disconnect(); }
			return disconnected;
		}

		/**
		 * Connects all inputs using the provided transactions. If any input cannot be connected returns that input or
		 * null on success.
		 */
		TransactionInput connectForReorganize(IDictionary<Sha256Hash,Transaction> transactions)
		{
			EnsureParsed();

			foreach(TransactionInput input in inputs)
			{
				// Coinbase transactions, by definition, do not have connectable inputs.
				if(input.IsCoinBase)
				{ continue; }

				TransactionInput.ConnectionResult result=input.connect(transactions, TransactionInput.ConnectMode.ABORT_ON_CONFLICT);
				// Connected to another tx in the wallet?
				if(result==TransactionInput.ConnectionResult.SUCCESS)
				{ continue; }
				
				// The input doesn't exist in the wallet, eg because it belongs to somebody else (inbound spend).
				if(result==TransactionInput.ConnectionResult.NO_SUCH_TX)
				{ continue; }

				// Could not connect this input, so return it and abort.
				return input;
			}
			return null;
		}

		/**
		 * Returns the earliest time at which the transaction was seen (broadcast or included into the chain),
		 * or the epoch if that information isn't available.
		 */
		public Date getUpdateTime()
		{
			if (updatedAt == null)
			{
				// Older wallets did not store this field. Set to the epoch.
				updatedAt = new Date(0);
			}
			return updatedAt;
		}
    
		public void setUpdateTime(Date updatedAt)
		{
			this.updatedAt = updatedAt;
		}

		/**
		 * These constants are a part of a scriptSig signature on the inputs. They define the details of how a
		 * transaction can be redeemed, specifically, they control how the hash of the transaction is calculated.
		 * <p/>
		 * In the official client, this enum also has another flag, SIGHASH_ANYONECANPAY. In this implementation,
		 * that's kept separate. Only SIGHASH_ALL is actually used in the official client today. The other flags
		 * exist to allow for distributed contracts.
		 */
		public enum SigHash
		{
			ALL=1,
			NONE=2,
			SINGLE=3
		}

		protected void unCache() {
			super.unCache();
			hash = null;
		}

		//throws ProtocolException 
		protected override void ParseLite()
		{
			//skip this if the length has been provided i.e. the tx is not part of a block
			if(ParseLazy && Length==UnknownLength)
			{
				//If length hasn't been provided this tx is probably contained within a block.
				//In parseRetain mode the block needs to know how long the transaction is
				//unfortunately this requires a fairly deep (though not total) parse.
				//This is due to the fact that transactions in the block's list do not include a
				//size header and inputs/outputs are also variable length due the contained
				//script so each must be instantiated so the scriptlength varint can be read
				//to calculate total length of the transaction.
				//We will still persist will this semi-light parsing because getting the lengths
				//of the various components gains us the ability to cache the backing bytearrays
				//so that only those subcomponents that have changed will need to be reserialized.

				//parse();
				//parsed = true;

				Length=calcLength(Bytes,Cursor,Offset);
				Cursor=Offset+Length;
			}
		}

		//throws ProtocolException
		protected override void Parse()
		{
			if(Parsed)
			{ return; }

			Cursor=Offset;

			version=ReadUint32();
			optimalEncodingMessageSize=4;

			// First come the inputs.
			VarInt numInputs=ReadVarInt();
			optimalEncodingMessageSize+=numInputs.SizeInBytes;

			inputs=new List<TransactionInput>((int)numInputs.Value);
			for(ulong i=0;i<numInputs.Value;i++)
			{
				inputs.Add(new TransactionInput(Parameters,this,Bytes,Cursor,ParseLazy,ParseRetain));
				VarInt scriptLen=ReadVarInt(TransactionOutPoint.MessageLength);
				optimalEncodingMessageSize+=TransactionOutPoint.MessageLength+scriptLen.SizeInBytes+scriptLen.Value+4;
				Cursor+=(int)scriptLen.Value+4;
			}

			// Now the outputs
			VarInt numOutputs=ReadVarInt();
			optimalEncodingMessageSize+=numOutputs.SizeInBytes;
			outputs=new List<TransactionOutput>((int)numOutputs.Value);
			for(ulong i=0;i<numOutputs.Value;i++)
			{
				outputs.Add(new TransactionOutput(Parameters,this,Bytes,Cursor,ParseLazy,ParseRetain));
				VarInt scriptLen=ReadVarInt(8);
				optimalEncodingMessageSize+=8+scriptLen.SizeInBytes+scriptLen.Value;
				Cursor+=(int)scriptLen.Value;
			}

			lockTime=ReadUint32();
			optimalEncodingMessageSize+=4;
			Length=Cursor-Offset;
		}

		protected static int calcLength(byte[] buf,int cursor,int offset)
		{
			VarInt varint;
			// jump past version (uint32)
			cursor = offset + 4;

			int i;
			long scriptLen;

			varint = new VarInt(buf, cursor);
			long txInCount = varint.value;
			cursor += varint.getOriginalSizeInBytes();

			for (i = 0; i < txInCount; i++) {
				// 36 = length of previous_outpoint
				cursor += 36;
				varint = new VarInt(buf, cursor);
				scriptLen = varint.value;
				// 4 = length of sequence field (unint32)
				cursor += scriptLen + 4 + varint.getOriginalSizeInBytes();
			}

			varint = new VarInt(buf, cursor);
			long txOutCount = varint.value;
			cursor += varint.getOriginalSizeInBytes();

			for (i = 0; i < txOutCount; i++) {
				// 8 = length of tx value field (uint64)
				cursor += 8;
				varint = new VarInt(buf, cursor);
				scriptLen = varint.value;
				cursor += scriptLen + varint.getOriginalSizeInBytes();
			}
			// 4 = length of lock_time field (uint32)
			return cursor - offset + 4;
		}

		
    
		public int getOptimalEncodingMessageSize()
		{
			if(optimalEncodingMessageSize!=0)
			{ return optimalEncodingMessageSize; }

			EnsureParsed();

			if(optimalEncodingMessageSize!=0)
			{ return optimalEncodingMessageSize; }

			optimalEncodingMessageSize=getMessageSize();
			return optimalEncodingMessageSize;
		}

		//public String toString() {
		//	return toString(null);
		//}

		///**
		// * A human readable version of the transaction useful for debugging. The format is not guaranteed to be stable.
		// * @param chain If provided, will be used to estimate lock times (if set). Can be null.
		// */
		//public String toString(ABlockChain chain)
		//{
		//	// Basic info about the tx.
		//	StringBuilder s=new StringBuilder();
		//	s.Append(string.Format("  {0}: {1}", getHashAsString(), getConfidence()));
		//	if (lockTime > 0) {
		//		String time;
		//		if (lockTime < LocktimeThreshold) {
		//			time = "block " + lockTime;
		//			if (chain != null) {
		//				time = time + " (estimated to be reached at " +
		//						chain.estimateBlockTime((int)lockTime).toString() + ")";
		//			}
		//		} else {
		//			time = new Date(lockTime).toString();
		//		}
		//		s.append(String.format("  time locked until %s%n", time));
		//	}
		//	if (inputs.size() == 0) {
		//		s.append(String.format("  INCOMPLETE: No inputs!%n"));
		//		return s.toString();
		//	}
		//	if (isCoinBase()) {
		//		String script;
		//		String script2;
		//		try {
		//			script = inputs.get(0).getScriptSig().toString();
		//			script2 = outputs.get(0).getScriptPubKey().toString();
		//		} catch (ScriptException e) {
		//			script = "???";
		//			script2 = "???";
		//		}
		//		return "     == COINBASE TXN (scriptSig " + script + ")  (scriptPubKey " + script2 + ")\n";
		//	}
		//	for (TransactionInput in : inputs) {
		//		s.append("     ");
		//		s.append("from ");

		//		try {
		//			Script scriptSig = in.getScriptSig();
		//			if (scriptSig.chunks.size() == 2)
		//				s.append(scriptSig.getFromAddress().toString());
		//			else if (scriptSig.chunks.size() == 1)
		//				s.append("[sig:" + bytesToHexString(scriptSig.getPubKey()) + "]");
		//			else
		//				s.append("???");
		//			s.append(" / ");
		//			s.append(in.getOutpoint().toString());
		//		} catch (Exception e) {
		//			s.append("[exception: ").append(e.getMessage()).append("]");
		//		}
		//		s.append(String.format("%n"));
		//	}
		//	for (TransactionOutput out : outputs) {
		//		s.append("       ");
		//		s.append("to ");
		//		try {
		//			Script scriptPubKey = out.getScriptPubKey();
		//			if (scriptPubKey.isSentToAddress()) {
		//				s.append(scriptPubKey.getToAddress().toString());
		//			} else if (scriptPubKey.isSentToRawPubKey()) {
		//				s.append("[pubkey:");
		//				s.append(bytesToHexString(scriptPubKey.getPubKey()));
		//				s.append("]");
		//			}
		//			s.append(" ");
		//			s.append(bitcoinValueToFriendlyString(out.getValue()));
		//			s.append(" BTC");
		//			if (!out.isAvailableForSpending()) {
		//				s.append(" Spent");
		//			}
		//			if (out.getSpentBy() != null) {
		//				s.append(" by ");
		//				s.append(out.getSpentBy().getParentTransaction().getHashAsString());
		//			}
		//		} catch (Exception e) {
		//			s.append("[exception: ").append(e.getMessage()).append("]");
		//		}
		//		s.append(String.format("%n"));
		//	}
		//	return s.toString();
		//}

		/**
		 * Adds an input to this transaction that imports value from the given output. Note that this input is NOT
		 * complete and after every input is added with addInput() and every output is added with addOutput(),
		 * signInputs() must be called to finalize the transaction and finish the inputs off. Otherwise it won't be
		 * accepted by the network.
		 */
		public void addInput(TransactionOutput from)
		{ addInput(new TransactionInput(Parameters,this,from)); }

		/**
		 * Adds an input directly, with no checking that it's valid.
		 */
		public void addInput(TransactionInput input)
		{
			unCache();
			input.setParent(this);
			inputs.add(input);
			adjustLength(inputs.size(), input.length);
		}

		/**
		 * Adds the given output to this transaction. The output must be completely initialized.
		 */
		public void addOutput(TransactionOutput to)
		{
			unCache();
			to.setParent(this);
			outputs.add(to);
			adjustLength(outputs.size(), to.length);
		}

		/**
		 * Creates an output based on the given address and value, adds it to this transaction.
		 */
		public void addOutput(BigInteger value, Address address)
		{ addOutput(new TransactionOutput(Parameters,this,value,address)); }

		/**
		 * Creates an output that pays to the given pubkey directly (no address) with the given value, and adds it to this
		 * transaction.
		 */
		public void addOutput(BigInteger value, ECKey pubkey)
		{ addOutput(new TransactionOutput(params, this, value, pubkey)); }

		///**
		// * Once a transaction has some inputs and outputs added, the signatures in the inputs can be calculated. The
		// * signature is over the transaction itself, to prove the redeemer actually created that transaction,
		// * so we have to do this step last.<p>
		// * <p/>
		// * This method is similar to SignatureHash in script.cpp
		// *
		// * @param hashType This should always be set to SigHash.ALL currently. Other types are unused.
		// * @param wallet   A wallet is required to fetch the keys needed for signing.
		// */
		//public synchronized void signInputs(SigHash hashType, Wallet wallet) throws ScriptException {
		//	Preconditions.checkState(inputs.size() > 0);
		//	Preconditions.checkState(outputs.size() > 0);

		//	// I don't currently have an easy way to test other modes work, as the official client does not use them.
		//	Preconditions.checkArgument(hashType == SigHash.ALL, "Only SIGHASH_ALL is currently supported");

		//	// The transaction is signed with the input scripts empty except for the input we are signing. In the case
		//	// where addInput has been used to set up a new transaction, they are already all empty. The input being signed
		//	// has to have the connected OUTPUT program in it when the hash is calculated!
		//	//
		//	// Note that each input may be claiming an output sent to a different key. So we have to look at the outputs
		//	// to figure out which key to sign with.

		//	byte[][] signatures = new byte[inputs.size()][];
		//	ECKey[] signingKeys = new ECKey[inputs.size()];
		//	for (int i = 0; i < inputs.size(); i++) {
		//		TransactionInput input = inputs[i];
		//		if (input.getScriptBytes().length != 0)
		//			log.warn("Re-signing an already signed transaction! Be sure this is what you want.");
		//		// Find the signing key we'll need to use.
		//		ECKey key = input.getOutpoint().getConnectedKey(wallet);
		//		// This assert should never fire. If it does, it means the wallet is inconsistent.
		//		Preconditions.checkNotNull(key, "Transaction exists in wallet that we cannot redeem: %s",
		//								   input.getOutpoint().getHash());
		//		// Keep the key around for the script creation step below.
		//		signingKeys[i] = key;
		//		// The anyoneCanPay feature isn't used at the moment.
		//		boolean anyoneCanPay = false;
		//		byte[] connectedPubKeyScript = input.getOutpoint().getConnectedPubKeyScript();
		//		Sha256Hash hash = hashTransactionForSignature(i, connectedPubKeyScript, hashType, anyoneCanPay);

		//		// Now sign for the output so we can redeem it. We use the keypair to sign the hash,
		//		// and then put the resulting signature in the script along with the public key (below).
		//		try {
		//			// Usually 71-73 bytes.
		//			ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(73);
		//			bos.write(key.sign(hash).encodeToDER());
		//			bos.write((hashType.ordinal() + 1) | (anyoneCanPay ? 0x80 : 0));
		//			signatures[i] = bos.toByteArray();
		//			bos.close();
		//		} catch (IOException e) {
		//			throw new RuntimeException(e);  // Cannot happen.
		//		}
		//	}

		//	// Now we have calculated each signature, go through and create the scripts. Reminder: the script consists:
		//	// 1) For pay-to-address outputs: a signature (over a hash of the simplified transaction) and the complete
		//	//    public key needed to sign for the connected output. The output script checks the provided pubkey hashes
		//	//    to the address and then checks the signature.
		//	// 2) For pay-to-key outputs: just a signature.
		//	for (int i = 0; i < inputs.size(); i++) {
		//		TransactionInput input = inputs[i];
		//		ECKey key = signingKeys[i];
		//		Script scriptPubKey = input.getOutpoint().getConnectedOutput().getScriptPubKey();
		//		if (scriptPubKey.isSentToAddress()) {
		//			input.setScriptBytes(Script.createInputScript(signatures[i], key.getPubKey()));
		//		} else if (scriptPubKey.isSentToRawPubKey()) {
		//			input.setScriptBytes(Script.createInputScript(signatures[i]));
		//		} else {
		//			// Should be unreachable - if we don't recognize the type of script we're trying to sign for, we should
		//			// have failed above when fetching the key to sign with.
		//			throw new RuntimeException("Do not understand script type: " + scriptPubKey);
		//		}
		//	}

		//	// Every input is now complete.
		//}

		/**
		 * Calculates a signature hash, that is, a hash of a simplified form of the transaction. How exactly the transaction
		 * is simplified is specified by the type and anyoneCanPay parameters.<p>
		 *
		 * You don't normally ever need to call this yourself. It will become more useful in future as the contracts
		 * features of Bitcoin are developed.
		 *
		 * @param inputIndex input the signature is being calculated for. Tx signatures are always relative to an input.
		 * @param connectedScript the bytes that should be in the given input during signing.
		 * @param type Should be SigHash.ALL
		 * @param anyoneCanPay should be false.
		 * @throws ScriptException if connectedScript is invalid
		 */
		public Sha256Hash hashTransactionForSignature(int inputIndex,byte[] connectedScript,SigHash type,bool anyoneCanPay)
		{
			return hashTransactionForSignature(inputIndex, connectedScript, (byte)((type.ordinal() + 1) | (anyoneCanPay ? 0x80 : 0x00)));
		}
    
		/**
		 * This is required for signatures which use a sigHashType which cannot be represented using SigHash and anyoneCanPay
		 * See transaction c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73, which has sigHashType 0
		 * throws ScriptException
		 */
		private Sha256Hash hashTransactionForSignature(int inputIndex,byte[] connectedScript,byte sigHashType)
		{
			lock(this)
			{
				// TODO: This whole separate method should be un-necessary if we fix how we deserialize sighash flags.
				// The SIGHASH flags are used in the design of contracts, please see this page for a further understanding of
				// the purposes of the code in this method:
				//
				//   https://en.bitcoin.it/wiki/Contracts
			
				try
				{
					// Store all the input scripts and clear them in preparation for signing. If we're signing a fresh
					// transaction that step isn't very helpful, but it doesn't add much cost relative to the actual
					// EC math so we'll do it anyway.
					//
					// Also store the input sequence numbers in case we are clearing them with SigHash.NONE/SINGLE
				
					byte[][] inputScripts = new byte[inputs.size()][];
					long[] inputSequenceNumbers = new long[inputs.size()];
					for (int i = 0; i < inputs.size(); i++)
					{
						inputScripts[i] = inputs[i].getScriptBytes();
						inputSequenceNumbers[i] = inputs[i].getSequenceNumber();
						inputs[i].setScriptBytes(TransactionInput.EMPTY_ARRAY);
					}
				
					// This step has no purpose beyond being synchronized with the reference clients bugs. OP_CODESEPARATOR
					// is a legacy holdover from a previous, broken design of executing scripts that shipped in Bitcoin 0.1.
					// It was seriously flawed and would have let anyone take anyone elses money. Later versions switched to
					// the design we use today where scripts are executed independently but share a stack. This left the
					// OP_CODESEPARATOR instruction having no purpose as it was only meant to be used internally, not actually
					// ever put into scripts. Deleting OP_CODESEPARATOR is a step that should never be required but if we don't
					// do it, we could split off the main chain.
				
					connectedScript = Script.removeAllInstancesOfOp(connectedScript, Script.OP_CODESEPARATOR);
				
					// Set the input to the script of its output. Satoshi does this but the step has no obvious purpose as
					// the signature covers the hash of the prevout transaction which obviously includes the output script
					// already. Perhaps it felt safer to him in some way, or is another leftover from how the code was written.
				
					TransactionInput input = inputs.get(inputIndex);
					input.setScriptBytes(connectedScript);
					ArrayList<TransactionOutput> outputs = this.outputs;
					if((sigHashType & 0x1f) == (SigHash.NONE.ordinal() + 1))
					{
						// SIGHASH_NONE means no outputs are signed at all - the signature is effectively for a "blank cheque".
						this.outputs = new ArrayList<TransactionOutput>(0);
					
						// The signature isn't broken by new versions of the transaction issued by other parties.
					
						for(int i=0;i<inputs.size();i++)
						{
							if (i != inputIndex)
							{ inputs[i].setSequenceNumber(0); }
						}
					}
					else if((sigHashType & 0x1f) == (SigHash.SINGLE.ordinal() + 1))
					{
						// SIGHASH_SINGLE means only sign the output at the same index as the input (ie, my output).
					
						if (inputIndex >= this.outputs.size())
						{
							// The input index is beyond the number of outputs, it's a buggy signature made by a broken
							// Bitcoin implementation. The reference client also contains a bug in handling this case:
							// any transaction output that is signed in this case will result in both the signed output
							// and any future outputs to this public key being steal-able by anyone who has
							// the resulting signature and the public key (both of which are part of the signed tx input).
							// Put the transaction back to how we found it.
							// TODO: Only allow this to happen if we are checking a signature, not signing a transactions
						
							for(int i=0;i<inputs.size();i++)
							{
								inputs[i].setScriptBytes(inputScripts[i]);
								inputs[i].setSequenceNumber(inputSequenceNumbers[i]);
							}
						
							this.outputs = outputs;
						
							// Satoshis bug is that SignatureHash was supposed to return a hash and on this codepath it
							// actually returns the constant "1" to indicate an error, which is never checked for. Oops.
							return new Sha256Hash("0100000000000000000000000000000000000000000000000000000000000000");
						}
					
						// In SIGHASH_SINGLE the outputs after the matching input index are deleted, and the outputs before
						// that position are "nulled out". Unintuitively, the value in a "null" transaction is set to -1.
					
						this.outputs = new ArrayList<TransactionOutput>(this.outputs.subList(0, inputIndex + 1));
						for (int i = 0; i < inputIndex; i++)
						{ this.outputs.set(i, new TransactionOutput(params, this, BigInteger.valueOf(-1), new byte[] {})); }
					
						// The signature isn't broken by new versions of the transaction issued by other parties.
						for(int i=0;i<inputs.size();i++)
						{
							if (i != inputIndex)
							{ inputs[i].setSequenceNumber(0); }
						}
					}
				
					ArrayList<TransactionInput> inputs = this.inputs;
				
					if((sigHashType & 0x80) == 0x80)
					{
						// SIGHASH_ANYONECANPAY means the signature in the input is not broken by changes/additions/removals
						// of other inputs. For example, this is useful for building assurance contracts.
					
						this.inputs = new ArrayList<TransactionInput>();
						this.inputs.add(input);
					}
				
					ByteArrayOutputStream bos = new UnsafeByteArrayOutputStream(length == UNKNOWN_LENGTH ? 256 : length + 4);
					bitcoinSerialize(bos);
				
					// We also have to write a hash type (sigHashType is actually an unsigned char)
					uint32ToByteStreamLE(0x000000ff & sigHashType, bos);
				
					// Note that this is NOT reversed to ensure it will be signed correctly. If it were to be printed out
					// however then we would expect that it is IS reversed.
					Sha256Hash hash = new Sha256Hash(doubleDigest(bos.toByteArray()));
					bos.close();
				
					// Put the transaction back to how we found it.
					this.inputs = inputs;
					for (int i = 0; i < inputs.size(); i++)
					{
						inputs[i].setScriptBytes(inputScripts[i]);
						inputs[i].setSequenceNumber(inputSequenceNumbers[i]);
					}
				
					this.outputs = outputs;
					return hash;
				}
				catch(IOException e)
				{
					throw new RuntimeException(e);  // Cannot happen.
				}
			}
		}

		//@Override
		//throws IOException
		protected void bitcoinSerializeToStream(OutputStream stream)
		{
			uint32ToByteStreamLE(version, stream);
			stream.write(new VarInt(inputs.size()).encode());
			foreach(TransactionInput input in inputs)
			{ input.bitcoinSerialize(stream); }
			stream.write(new VarInt(outputs.size()).encode());
			foreach(TransactionOutput output in outputs)
			{ output.bitcoinSerialize(stream); }
			uint32ToByteStreamLE(lockTime,stream);
		}


		/**
		 * @return the lockTime
		 */
		public long getLockTime()
		{
			maybeParse();
			return lockTime;
		}

		/**
		 * @param lockTime the lockTime to set
		 */
		public void setLockTime(long lockTime)
		{
			unCache();
			this.lockTime = lockTime;
		}

		/**
		 * @return the version
		 */
		public long getVersion()
		{
			maybeParse();
			return version;
		}

		/**
		 * @return a read-only list of the inputs of this transaction.
		 */
		public List<TransactionInput> getInputs()
		{
			maybeParse();
			return Collections.unmodifiableList(inputs);
		}

		/**
		 * @return a read-only list of the outputs of this transaction.
		 */
		public List<TransactionOutput> getOutputs()
		{
			maybeParse();
			return Collections.unmodifiableList(outputs);
		}

		/** @return the given transaction: same as getInputs().get(index). */
		public TransactionInput getInput(int index)
		{
			maybeParse();
			return inputs.get(index);
		}

		public TransactionOutput getOutput(int index)
		{
			maybeParse();
			return outputs.get(index);
		}
    
		public TransactionConfidence getConfidence()
		{
			lock(this)
			{
				if (confidence == null)
				{confidence = new TransactionConfidence(this);}
				return confidence;
			}
		}

		/** Check if the transaction has a known confidence */
		public synchronized boolean hasConfidence()
		{
			return confidence != null && confidence.getConfidenceType() != TransactionConfidence.ConfidenceType.UNKNOWN;
		}

		@Override
		public boolean equals(Object other) {
			if (!(other instanceof Transaction)) return false;
			Transaction t = (Transaction) other;

			return t.getHash().equals(getHash());
		}

		@Override
		public int hashCode() {
			return getHash().hashCode();
		}

		/**
		 * Ensure object is fully parsed before invoking java serialization.  The backing byte array
		 * is transient so if the object has parseLazy = true and hasn't invoked checkParse yet
		 * then data will be lost during serialization.
		 */
		private void writeObject(ObjectOutputStream out) throws IOException {
			maybeParse();
			out.defaultWriteObject();
		}
    
		/**
		 * Gets the count of regular SigOps in this transactions
		 */
		public int getSigOpCount() throws ScriptException {
			maybeParse();
			int sigOps = 0;
			for (TransactionInput input : inputs)
				sigOps += Script.getSigOpCount(input.getScriptBytes());
			for (TransactionOutput output : outputs)
				sigOps += Script.getSigOpCount(output.getScriptBytes());
			return sigOps;
		}

		/**
		 * Checks the transaction contents for sanity, in ways that can be done in a standalone manner.
		 * Does <b>not</b> perform all checks on a transaction such as whether the inputs are already spent.
		 *
		 * @throws VerificationException
		 */
		public void verify() throws VerificationException {
			maybeParse();
			if (inputs.size() == 0 || outputs.size() == 0)
				throw new VerificationException("Transaction had no inputs or no outputs.");
			if (this.getMessageSize() > Block.MAX_BLOCK_SIZE)
				throw new VerificationException("Transaction larger than MAX_BLOCK_SIZE");
        
			BigInteger valueOut = BigInteger.ZERO;
			for (TransactionOutput output : outputs) {
				if (output.getValue().compareTo(BigInteger.ZERO) < 0)
					throw new VerificationException("Transaction output negative");
				valueOut = valueOut.add(output.getValue());
			}
			if (valueOut.compareTo(params.MAX_MONEY) > 0)
				throw new VerificationException("Total transaction output value greater than possible");
        
			if (isCoinBase()) {
				if (inputs.get(0).getScriptBytes().length < 2 || inputs.get(0).getScriptBytes().length > 100)
					throw new VerificationException("Coinbase script size out of range");
			} else {
				for (TransactionInput input : inputs)
					if (input.isCoinBase())
						throw new VerificationException("Coinbase input as input in non-coinbase transaction");
			}
		}

		/**
		 * <p>Returns true if this transaction is considered finalized and can be placed in a block. Non-finalized
		 * transactions won't be included by miners and can be replaced with newer versions using sequence numbers.
		 * This is useful in certain types of <a href="http://en.bitcoin.it/wiki/Contracts">contracts</a>, such as
		 * micropayment channels.</p>
		 *
		 * <p>Note that currently the replacement feature is disabled in the Satoshi client and will need to be
		 * re-activated before this functionality is useful.</p>
		 */
		public boolean isFinal(int height, long blockTimeSeconds) {
			// Time based nLockTime implemented in 0.1.6
			long time = getLockTime();
			if (time == 0)
				return true;
			if (time < (time < LOCKTIME_THRESHOLD ? height : blockTimeSeconds))
				return true;
			for (TransactionInput in : inputs)
				if (in.hasSequence())
					return false;
			return true;
		}

		/**
		 * Parses the string either as a whole number of blocks, or if it contains slashes as a YYYY/MM/DD format date
		 * and returns the lock time in wire format.
		 */
		public static long parseLockTimeStr(String lockTimeStr) throws ParseException {
			if (lockTimeStr.indexOf("/") != -1) {
				SimpleDateFormat format = new SimpleDateFormat("yyyy/MM/dd");
				Date date = format.parse(lockTimeStr);
				return date.getTime() / 1000;
			}
			return Long.parseLong(lockTimeStr);
		}

		/**
		 * Returns either the lock time as a date, if it was specified in seconds, or an estimate based on the time in
		 * the current head block if it was specified as a block time.
		 */
		public Date estimateLockTime(AbstractBlockChain chain) {
			if (lockTime < LOCKTIME_THRESHOLD)
				return chain.estimateBlockTime((int)getLockTime());
			else
				return new Date(getLockTime()*1000);
		}
	}
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Security;
using System.Text;
using BitcoinNET.BitcoinObjects.Abstractions;
using BitcoinNET.BitcoinObjects.Exceptions;
using BitcoinNET.BitcoinObjects.Parameters.Abstractions;
using BitcoinNET.Utils;
using BitcoinNET.Utils.Extensions;
using BitcoinNET.Utils.Objects;
using Org.BouncyCastle.Math;

namespace BitcoinNET.BitcoinObjects
{
	[Serializable]
	public class Block:AMessage
	{
		public const int HeaderSize=80;				//How many bytes are required to represent a block header.
		public const long AllowedTimeDrift=2*60*60; //Same value as official client.
		public const int MaxBlockSize=1*1000*1000;	//A constant shared by the entire network: how large in bytes a block is allowed to be. One day we may have to upgrade everyone to change this, so Bitcoin can continue to grow. For now it exists as an anti-DoS measure to avoid somebody creating a titanically huge but valid block and forcing everyone to download/store it forever.
		public const int MaxBlockSigops=MaxBlockSize/50;	//A "sigop" is a signature verification operation. Because they're expensive we also impose a separate limit on the number in a block to prevent somebody mining a huge block that has way more sigops than normal, so is very expensive/slow to verify.
		public const long EasiestDifficultyTarget=0x207fFFFFL;	//A value for difficultyTarget (nBits) that allows half of all possible hash solutions. Used in unit testing.

		public static readonly BigInteger LargestHash=BigInteger.One.ShiftLeft(256);	//The number that is one greater than the largest representable SHA-256 hash.

		public static ulong FakeClock=0;	// For unit testing. If not zero, use this instead of the current time.
		
		[NonSerialized]private bool headerParsed;
		[NonSerialized]private bool transactionsParsed;
		[NonSerialized]private bool headerBytesValid;
		[NonSerialized]private bool transactionBytesValid;

		

		private uint version;
		public uint Version
		{
			get
			{
				EnsureParsedHeader();
				return version;
			}
			private set { version=value; }
		}   //Returns the version of the block data structure as defined by the Bitcoin protocol

		private Sha256Hash hash;
		public override Sha256Hash Hash
		{ get { return hash??(hash=new Sha256Hash(DoubleDigestSha256Helper.DoubleDigest(getHeader()).ReverseBytes())); } }	//Returns the hash of the block (which for a valid, solved block should be below the target). Big endian.

		private string hashString;
		public string HashString
		{
			get
			{ return hashString??(hashString=Hash.ToString()); }
		}	//Returns the hash of the block (which for a valid, solved block should be below the target) in the form seen on the block explorer. If you call this on block 1 in the production chain you will get "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048".

		private Sha256Hash previousBlockHash;
		public Sha256Hash PreviousBlockHash
		{
			get
			{
				EnsureParsedHeader();
				return previousBlockHash;
			}
			private set
			{
				previousBlockHash=value;
				hash=null;
			}
		}

		private Sha256Hash ____merkleRoot;
		public Sha256Hash MerkleRoot
		{
			get { return ____merkleRoot??(____merkleRoot=CalculateMerkleRoot()); }
			set
			{
				____merkleRoot=value;
				hash=null;
			}
		}

		private uint difficultyTarget; // "nBits"
		public uint DifficultyTarget
		{
			get
			{
				EnsureParsedHeader();
				return difficultyTarget;
			}
			set
			{
				difficultyTarget=value;
				difficultyTargetAsInteger=null;
				hash=null;
			}
		}	//Returns the difficulty of the proof of work that this block should meet encoded in compact form. The BlockChain verifies that this is not too easy by looking at the length of the chain when the block is added. To find the actual value the hash should be compared against, use getDifficultyTargetBI.

		[NonSerialized]private BigInteger difficultyTargetAsInteger;
		public BigInteger DifficultyTargetAsInteger
		{
			get
			{
				if(difficultyTargetAsInteger==null)
				{
					EnsureParsedHeader();
					BigInteger target=DifficultyTarget.DecodeCompactBits();

					if(target.CompareTo(BigInteger.Zero)<=0 || target.CompareTo(Parameters.ProofOfWorkLimit)>0)
					{ throw new VerificationException("Difficulty target is bad: "+target); }
					difficultyTargetAsInteger=target;
				}

				return difficultyTargetAsInteger;
			}
		}		//Returns the difficulty target as a 256 bit value that can be compared to a SHA-256 hash. Inside a block the target is represented using a compact form. If this form decodes to a value that is out of bounds, an exception is thrown.


		private uint nonce;
		public uint Nonce
		{
			get
			{
				EnsureParsedHeader();
				return nonce;
			}
			set
			{
				nonce=value;
				hash=null;
			}
		}

		private uint timeSeconds;
		public uint TimeSeconds
		{
			get
			{
				EnsureParsedHeader();
				return timeSeconds;
			}
			private set
			{
				timeSeconds=value;
				hash=null;
				date=null;
			}
		}
		
		private DateTime? date;
		public DateTime Date
		{ get { return (date??(date=UnixTimeHelper.FromUnixTime(TimeSeconds))).Value; } }

		/// <summary>
		/// Blocks can be encoded in a way that will use more bytes than is optimal (due to VarInts having multiple encodings)
		/// MaxBlockSize must be compared to the optimal encoding, not the actual encoding, so when parsing, we keep track
		/// of the size of the ideal encoding in addition to the actual message size (which Message needs)
		/// </summary>
		[NonSerialized]private int optimalEncodingMessageSize;
		public int OptimalEncodingMessageSize
		{
			get
			{
				if(optimalEncodingMessageSize==0)
				{
					EnsureParsedTransactions();

					if(optimalEncodingMessageSize==0)
					{ optimalEncodingMessageSize=MessageSize; }
				}
				return optimalEncodingMessageSize;
			}
			set { optimalEncodingMessageSize=value; }
		}

		public IList<Transaction> Transactions;	//If null, it means this object holds only the headers


		/// <summary>
		/// Special case constructor, used for the genesis node, cloneAsHeader and unit tests.
		/// </summary>
		/// <param name="parameters"></param>
		public Block(NetworkParameters parameters):base(parameters)
		{
			// Set up a few basic things. We are not complete after this though.
			version=1;
			difficultyTarget=(uint)0x1d07fff8L;
			TimeSeconds=UnixTimeHelper.ToUnixTime(DateTime.UtcNow);
			PreviousBlockHash=Sha256Hash.ZeroHash;
			Length=80;
		}

		/// <summary>
		/// Constructs a block object from the Bitcoin wire format
		/// <exception cref="ProtocolException"/>
		/// </summary>
		/// <param name="parameters"></param>
		/// <param name="payloadBytes"></param>
		public Block(NetworkParameters parameters,byte[] payloadBytes):base(parameters,payloadBytes,0,false,false,payloadBytes.Length)
		{ }

		/// <summary>
		/// Contruct a block object from the BitCoin wire format
		/// <exception cref="ProtocolException"/>
		/// </summary>
		/// <param name="parameters">NetworkParameters object</param>
		/// <param name="payloadBytes"></param>
		/// <param name="parseLazy">Whether to perform a full parse immediately or delay until a read is requested</param>
		/// <param name="parseRetain">
		/// Whether to retain the backing byte array for quick reserialization.
		/// If true and the backing byte array is invalidated due to modification of a field then the cached bytes may be repopulated and retained if the message is serialized again in the future.</param>
		/// <param name="length">
		/// The length of message if known. Usually this is provided when deserializing of the wire as the length will be provided as part of the header.
		/// If unknown then set to Message.UnknwonLength</param>
		public Block(NetworkParameters parameters,byte[] payloadBytes,bool parseLazy,bool parseRetain,int length):base(parameters,payloadBytes,0,parseLazy,parseRetain,length)
		{ }

		

		/////throws ClassNotFoundException, IOException
		//private void readObject(ObjectInputStream ois)
		//{
		//	ois.defaultReadObject();
		//	// This code is not actually necessary, as transient fields are initialized to the default value which is in
		//	// this case null. However it clears out a FindBugs warning and makes it explicit what we're doing.
		//	hash = null;
		//}

		private void parseHeader()
		{
			if(headerParsed)
			{ return; }

			Cursor=Offset;
			Version=ReadUint32();
			PreviousBlockHash=ReadHash();
			MerkleRoot=ReadHash();
			TimeSeconds=ReadUint32();
			difficultyTarget=ReadUint32();
			nonce=ReadUint32();

			hash=new Sha256Hash(DoubleDigestSha256Helper.DoubleDigest(Bytes,Offset,Cursor).ReverseBytes());

			headerParsed=true;
			headerBytesValid=ParseRetain;
		}

		/// <summary>
		/// <exception cref="ProtocolException"/>
		/// </summary>
		private void parseTransactions()
		{
			if(transactionsParsed)
			{ return; }

			Cursor=Offset+HeaderSize;
			optimalEncodingMessageSize=HeaderSize;

			if(Bytes.Length==Cursor)
			{
				// This message is just a header, it has no transactions.
				transactionsParsed=true;
				transactionBytesValid=false;
				return;
			}

			ulong numTransactions=ReadVarInt().Value;
			optimalEncodingMessageSize+=VarInt.SizeInBytesOf(numTransactions);

			Transactions=new List<Transaction>((int)numTransactions);
			for(ulong i=0;i<numTransactions;i++)
			{
				Transaction tx=new Transaction(Parameters,Bytes,Cursor,this,ParseLazy,ParseRetain,UnknownLength);
				Transactions.Add(tx);
				Cursor+=tx.MessageSize;
				optimalEncodingMessageSize+=tx.OptimalEncodingMessageSize;
			}

			// No need to set length here. If length was not provided then it should be set at the end of parseLight().
			// If this is a genuine lazy parse then length must have been provided to the constructor.
			transactionsParsed=true;
			transactionBytesValid=ParseRetain;
		}

		/// <summary>
		/// <exception cref="ProtocolException"/>
		/// </summary>
		protected override void ParseLite()
		{
			// Ignore the header since it has fixed length. If length is not provided we will have to invoke a light parse of transactions to calculate the length.
			if (Length==UnknownLength)
			{
				//Performing lite parse of block transaction as block was initialised from byte array without providing length.  This should never need to happen.
				parseTransactions();
				Length=Cursor-Offset;
			}
			else
			{ transactionBytesValid=(!transactionsParsed || ParseRetain) && Length>HeaderSize; }
			headerBytesValid=(!headerParsed || ParseRetain) && Length>=HeaderSize;
		}

		/// <summary>
		/// <exception cref="ProtocolException"/>
		/// </summary>
		protected override void Parse()
		{
			parseHeader();
			parseTransactions();
			Length=Cursor-Offset;
		}

		/// <summary>
		/// In lazy parsing mode access to getters and setters may throw an unchecked LazyParseException.
		/// If guaranteed safe access is required this method will force parsing to occur immediately thus ensuring LazyParseExeption will
		/// never be thrown from this Message. If the Message contains child messages (e.g. a Block containing Transaction messages) this will not force child messages to parse.
		/// This method ensures parsing of both headers and transactions.
		/// <exception cref="ProtocolException"/>
		/// </summary>
		public override void EnsureParsed()
		{
			EnsureParsedHeader();
			EnsureParsedTransactions();
		}

		/*
		 * Block uses some special handling for lazy parsing and retention of cached bytes. Parsing and serializing the
		 * block header and the transaction list are both non-trivial so there are good efficiency gains to be had by
		 * separating them. There are many cases where a user may need access to access or change one or the other but not both.
		 *
		 * With this in mind we ignore the inherited checkParse() and unCache() methods and implement a separate version
		 * of them for both header and transactions.
		 *
		 * Serializing methods are also handled in their own way. Whilst they deal with separate parts of the block structure
		 * there are some interdependencies. For example altering a tx requires invalidating the Merkle root and therefore
		 * the cached header bytes.
		 */
		public void EnsureParsedHeader()
		{
			if(headerParsed || Bytes==null)
			{ return; }

			parseHeader();

			if(!(headerBytesValid || transactionBytesValid))
			{ Bytes=null; }
		}

		public void EnsureParsedTransactions()
		{
			if(transactionsParsed || Bytes==null)
			{ return; }

			parseTransactions();
			
			if(!ParseRetain)
			{
				transactionBytesValid=false;
				if(headerParsed)
				{ Bytes=null; }
			}
		}

		private byte[] getHeader()
		{
			// try for cached write first
			byte[] cachedHeader=getCachedHeader();
			if(cachedHeader!=null)
			{ return cachedHeader; }

			// fall back to manual write
			using(MemoryStream stream=new MemoryStream(HeaderSize))
			{
				___writeHeader(stream);
				return stream.ToArray();
			}
		}
		private void ___writeHeader(Stream stream)
		{
			// try for cached write first
			byte[] cachedHeader=getCachedHeader();
			if(cachedHeader!=null)
			{
				stream.Write(cachedHeader);
				return;
			}

			EnsureParsedHeader();
			stream.Write(Version.ToByteArrayLe());
			stream.Write(PreviousBlockHash.Bytes.ReverseBytes());
			stream.Write(MerkleRoot.Bytes.ReverseBytes());
			stream.Write(TimeSeconds.ToByteArrayLe());
			stream.Write(DifficultyTarget.ToByteArrayLe());
			stream.Write(Nonce.ToByteArrayLe());
		}
		private byte[] getCachedHeader()
		{
			if(headerBytesValid && Bytes!=null && Bytes.Length>=Offset+HeaderSize)
			{ return Bytes; }
			return null;
		}

		private byte[] getTransactions()
		{
			// Check for no transaction conditions first
			if(Transactions==null && transactionsParsed)
			{ return new byte[0]; }

			using(MemoryStream stream=new MemoryStream(Length==UnknownLength?HeaderSize+guessTransactionsLength():Length))
			{
				___writeTransactions(stream);
				return stream.ToArray();
			}
		}
		private void ___writeTransactions(Stream stream)
		{
			// Check for no transaction conditions first
			if(Transactions==null && transactionsParsed)
			{ return; }

			// Confirmed we must have transactions either cached or as objects.
			if(transactionBytesValid && Bytes!=null && Bytes.Length>=Offset+Length)
			{
				stream.Write(Bytes,Offset+HeaderSize,Length-HeaderSize);
				return;
			}

			if(Transactions!=null)
			{
				byte[] buffer=new VarInt((ulong)Transactions.Count).Encode();
				stream.Write(buffer,0,buffer.Length);

				foreach(Transaction tx in Transactions)
				{ tx.BitcoinSerializeToStream(stream); }
			}
		}

		/// <summary>
		/// Special handling to check if we have a valid byte array for both header and transactions
		/// </summary>
		/// <returns></returns>
		public override byte[] BitcoinSerialize()
		{
			byte[] cached=getCachedBitcoinSerialization();
			if(cached!=null)
			{ return cached; }

			// At least one of the two cacheable components is invalid
			// so fall back to stream write since we can't be sure of the length.
			using(ByteStreamUnsafe stream=new ByteStreamUnsafe(Length==UnknownLength?HeaderSize+guessTransactionsLength():Length))
			{
				BitcoinSerializeToStream(stream);
				return stream.GetWritenStreamIrreversible();
			}
		}
		public override void BitcoinSerializeToStream(Stream stream)
		{
			byte[] cached=getCachedBitcoinSerialization();
			if(cached!=null)
			{
				stream.Write(cached);
				return;
			}

			___writeHeader(stream);
			// We may only have enough data to write the header.
			___writeTransactions(stream);
		}
		private byte[] getCachedBitcoinSerialization()
		{
			// We have completely cached byte array.
			if(headerBytesValid && transactionBytesValid)
			{
				//Bytes should never be null if headerBytesValid && transactionBytesValid
				if(Length==Bytes.Length)
				{ return Bytes; }

				// byte array is offset so copy out the correct range.
				return Bytes.Duplicate(Offset,Length);
			}
			return null;
		}

		/// <summary>
		/// Provides a reasonable guess at the byte length of the transactions part of the block.
		/// The returned value will be accurate in 99% of cases and in those cases where not will probably slightly oversize.
		/// This is used to preallocate the underlying byte array for a Stream.
		/// If the size is under the real value the only penalty is resizing of the underlying byte array.
		/// </summary>
		/// <returns></returns>
		private int guessTransactionsLength()
		{
			if(transactionBytesValid)
			{ return Bytes.Length-HeaderSize; }

			if(Transactions==null)
			{ return 0; }

			int len=VarInt.SizeInBytesOf((ulong)Transactions.Count);
			foreach(Transaction tx in Transactions)
			{ len+=tx.MessageSize==UnknownLength?255:tx.MessageSize; }	// 255 is just a guess at an average tx length
			return len;
		}

		/// <summary>
		/// Returns the work represented by this block.
		/// Work is defined as the number of tries needed to solve a block in the average case.
		/// Consider a difficulty target that covers 5% of all possible hash values.
		/// Then the work of the block will be 20.
		/// As the target gets lower, the amount of work goes up.
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		/// <returns></returns>
		public BigInteger getWork()
		{ return LargestHash.Divide(getDifficultyTargetAsInteger().Add(BigInteger.One)); }

		/// <summary>
		/// Returns a copy of the block, but without any transactions.
		/// </summary>
		/// <returns></returns>
		public Block cloneAsHeader()
		{
			EnsureParsedHeader();

			return new Block(Parameters) {
				nonce=nonce,
				PreviousBlockHash=PreviousBlockHash.Duplicate(),
				MerkleRoot=MerkleRoot.Duplicate(),
				Version=Version,
				TimeSeconds=TimeSeconds,
				DifficultyTarget=DifficultyTarget,
				Transactions=null,
				hash=Hash.Duplicate()
			};
		}
		
		/// <summary>
		/// Returns a multi-line string containing a description of the contents of the block.
		/// Use for debugging purposes only.
		/// </summary>
		/// <returns></returns>
		public override string ToString()
		{
			StringBuilder builder=new StringBuilder(string.Format(@"v{0} block:
	previous block: {1}
	merkle root: {2}\n
	time: [{3}] {4}
	difficulty target (nBits): {5}
	nonce: {6}\n",
				version,									//0
				PreviousBlockHash,							//1
				MerkleRoot,									//2
				TimeSeconds,								//3
				UnixTimeHelper.FromUnixTime(TimeSeconds),	//4
				DifficultyTarget,							//5
				Nonce)										//6
			);

			if(Transactions!=null && Transactions.Count>0)
			{
				builder.AppendLine(string.Format("   with {0} transaction(s):",Transactions.Count));
				foreach(Transaction tx in Transactions)
				{ builder.Append(tx); }
			}

			return builder.ToString();
		}

		 
		/// <summary>
		/// Finds a value of nonce that makes the blocks hash lower than the difficulty target.
		/// This is called mining, but this is far too slow to do real mining with. It exists only for unit testing purposes.
		/// This can loop forever if a solution cannot be found solely by incrementing nonce. It doesn't change extraNonce.
		/// </summary>
		public void solve()
		{
			EnsureParsedHeader();
			while(true)
			{
				if(checkProofOfWork())
				{ return; }
				
				// No, so increment the nonce and try again.
				Nonce++;
			}
		}

		

		/// <summary>
		/// Returns true if the hash of the block is OK (lower than difficulty target).
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		/// <param name="throwException"></param>
		/// <returns></returns>
		private bool checkProofOfWork(bool throwException=false)
		{
			// This part is key - it is what proves the block was as difficult to make as it claims
            // to be. Note however that in the context of this function, the block can claim to be
            // as difficult as it wants to be .... if somebody was able to take control of our network
            // connection and fork us onto a different chain, they could send us valid blocks with
            // ridiculously easy difficulty and this function would accept them.
            //
            // To prevent this attack from being possible, elsewhere we check that the difficultyTarget
            // field is of the right value. This requires us to have the preceding blocks.
            
			BigInteger h=Hash.ToBigInteger();
            if(h.CompareTo(DifficultyTargetAsInteger)>0)
            {
				if(throwException)
				{ throw new VerificationException("Hash is higher than target: "+HashString+" vs "+DifficultyTargetAsInteger.ToString(16)); }
	            return false;
            }
            return true;
		}

		/// <summary>
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		private void checkTimestamp()
		{
			EnsureParsedHeader();

			// Allow injection of a fake clock to allow unit testing.
            ulong currentTime=FakeClock>0?FakeClock:UnixTimeHelper.ToUnixTime(DateTime.UtcNow);
            if(TimeSeconds>currentTime+AllowedTimeDrift)
			{ throw new VerificationException("Block too far in future"); }
		}

		/// <summary>
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		private void checkSigOps()
		{
			// Check there aren't too many signature verifications in the block. This is an anti-DoS measure, see the comments for MaxBlockSigops.
			int sigOps=0;
			foreach(Transaction tx in Transactions)
			{ sigOps+=tx.GetSigOpCount(); }

			if(sigOps>MaxBlockSigops)
			{ throw new VerificationException("Block had too many Signature Operations"); }
		}

		//throws VerificationException
		private void checkMerkleRoot()
		{
			Sha256Hash calculatedRoot=CalculateMerkleRoot();
            if(!calculatedRoot.Equals(MerkleRoot))
            { throw new VerificationException("Merkle hashes do not match: "+calculatedRoot+" vs "+MerkleRoot); }
		}

		private Sha256Hash calculateMerkleRoot()
		{
			List<byte[]> tree=buildMerkleTree();
			return new Sha256Hash(tree[tree.Count-1]);
		}

		private List<byte[]> buildMerkleTree()
		{
			// The Merkle root is based on a tree of hashes calculated from the transactions:
			//
			//     root
			//      / \
			//   A      B
			//  / \    / \
			// t1 t2 t3 t4
			//
			// The tree is represented as a list: t1,t2,t3,t4,A,B,root where each
			// entry is a hash.
			//
			// The hashing algorithm is double SHA-256. The leaves are a hash of the serialized contents of the transaction.
			// The interior nodes are hashes of the concenation of the two child hashes.
			//
			// This structure allows the creation of proof that a transaction was included into a block without having to
			// provide the full block contents. Instead, you can provide only a Merkle branch. For example to prove tx2 was
			// in a block you can just provide tx2, the hash(tx1) and B. Now the other party has everything they need to
			// derive the root, which can be checked against the block header. These proofs aren't used right now but
			// will be helpful later when we want to download partial block contents.
			//
			// Note that if the number of transactions is not even the last tx is repeated to make it so (see
			// tx3 above). A tree with 5 transactions would look like this:
			//
			//         root
			//        /     \
			//       1        5
			//     /   \     / \
			//    2     3    4  4
			//  / \   / \   / \
			// t1 t2 t3 t4 t5 t5

			EnsureParsedTransactions();
			List<byte[]> tree=new List<byte[]>();

			// Start by adding all the hashes of the transactions as leaves of the tree.
			foreach(Transaction transaction in Transactions)
			{ tree.Add(transaction.Hash.Bytes); }

			int levelOffset=0; // Offset in the list where the currently processed level starts.
        
			// Step through each level, stopping when we reach the root (levelSize == 1).
			for(int levelSize=Transactions.Count;levelSize>1;levelSize=(levelSize+1)/2)
			{
				// For each pair of nodes on that level:
				for(int left=0;left<levelSize;left+=2)
				{
					// The right hand node can be the same as the left hand, in the case where we don't have enough transactions.
					int right=Math.Min(left+1,levelSize-1);
					byte[] leftBytes=tree[levelOffset+left].ReverseBytes();
					byte[] rightBytes=tree[levelOffset+right].ReverseBytes();
					tree.Add(DoubleDigestSha256Helper.DoubleDigestTwoBuffers(leftBytes,0,32,rightBytes,0,32).ReverseBytes());
				}

				// Move to the next level.
				levelOffset+=levelSize;
			}
			return tree;
		}

		/// <summary>
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		private void checkTransactions()
		{
			// The first transaction in a block must always be a coinbase transaction.
			if (!Transactions[0].IsCoinBase)
			{ throw new VerificationException("First tx is not coinbase"); }
			
			// The rest must not be.
			for(int i=1;i<Transactions.Count;i++)
			{
				if(Transactions[i].IsCoinBase)
				{ throw new VerificationException("TX "+i+" is coinbase when it should not be."); }
			}
		}
		
		/// <summary>
		/// Checks the block data to ensure it follows the rules laid out in the network parameters.
		/// Specifically, throws an exception if the proof of work is invalid, or if the timestamp is too far from what it should be.
		/// This is <b>not</b> everything that is required for a block to be valid, only what is checkable independent of the chain and without a transaction index.
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		public void verifyHeader()
		{
			// Prove that this block is OK. It might seem that we can just ignore most of these checks given that the
			// network is also verifying the blocks, but we cannot as it'd open us to a variety of obscure attacks.
			//
			// Firstly we need to ensure this block does in fact represent real work done. If the difficulty is high
			// enough, it's probably been done by the network.
			EnsureParsedHeader();
			checkProofOfWork(true);
			checkTimestamp();
		}

		/// <summary>
		/// Checks the block contents.
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		public void verifyTransactions()
		{
			// Now we need to check that the body of the block actually matches the headers. The network won't generate
			// an invalid block, but if we didn't validate this then an untrusted man-in-the-middle could obtain the next
			// valid block from the network and simply replace the transactions in it with their own fictional
			// transactions that reference spent or non-existant inputs.
			if(Transactions==null || Transactions.Count<=0)
			{ throw new VerificationException("Block had no transactions"); }

			EnsureParsedTransactions();

			if(OptimalEncodingMessageSize>MaxBlockSize)
			{ throw new VerificationException("Block larger than MaxBlockSize"); }

			checkTransactions();
			checkMerkleRoot();
			checkSigOps();

			foreach(Transaction transaction in Transactions)
			{ transaction.Verify(); }
		}

		/// <summary>
		/// Verifies both the header and that the transactions hash to the merkle root.
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		public void verify()
		{
			verifyHeader();
			verifyTransactions();
		}

		private Sha256Hash CalculateMerkleRoot()
        {
            List<byte[]> tree=buildMerkleTree();
            return new Sha256Hash(tree[tree.Count-1]);
        }

		/// <summary>
		/// Adds a transaction to this block. The nonce and merkle root are invalid after this.
		/// </summary>
		/// <param name="transaction"></param>
		public void addTransaction(Transaction transaction)
		{ addTransaction(transaction,false); }

		/// <summary>
		/// Adds a transaction to this block, with or without checking the sanity of doing so.
		/// <exception cref="VerificationException"></exception>
		/// </summary>
		/// <param name="transaction"></param>
		/// <param name="runSanityChecks"></param>
		public void addTransaction(Transaction transaction,bool runSanityChecks)
		{
			if(Transactions==null)
			{ Transactions=new List<Transaction>(); }

			transaction.SetParent(this);

			if(runSanityChecks)
			{
				if(Transactions.Count==0 && !transaction.IsCoinBase)
				{ throw new VerificationException("Attempted to add a non-coinbase transaction as the first transaction: "+t); }
			
				if(Transactions.Count>0 && transaction.IsCoinBase)
				{ throw new VerificationException("Attempted to add a coinbase transaction when there already is one: "+t); }
			}
			

			Transactions.Add(transaction);
			AdjustLength(Transactions.Count,transaction.Length);
			
			// Force a recalculation next time the values are needed.
			MerkleRoot=null;
			hash=null;
		}

		

		//// ///////////////////////////////////////////////////////////////////////////////////////////////
		//// Unit testing related methods.

		//// Used to make transactions unique.
		//private static int txCounter;
		//public static readonly byte[] EmptyBytes=new byte[32];

		///** Adds a coinbase transaction to the block. This exists for unit tests. */
		//void addCoinbaseTransaction(byte[] pubKeyTo,BigInteger value)
		//{
		//	Transactions=new List<Transaction>();
		//	Transaction coinbase=new Transaction(Parameters);

		//	// A real coinbase transaction has some stuff in the scriptSig like the extraNonce and difficulty. The
		//	// transactions are distinguished by every TX output going to a different key.
		//	//
		//	// Here we will do things a bit differently so a new address isn't needed every time. We'll put a simple
		//	// counter in the scriptSig so every transaction has a different hash.
		//	coinbase.AddInput(new TransactionInput(Parameters,coinbase,new[] { (byte)txCounter++,(byte)1 }));
		//	coinbase.AddOutput(new TransactionOutput(Parameters,coinbase,value, Script.createOutputScript(pubKeyTo)));
		//	Transactions.Add(coinbase);
		//	coinbase.SetParent(this);
		//	coinbase.Length=coinbase.BitcoinSerialize().Length;
		//	AdjustLength(Transactions.Count,coinbase.Length);
		//}

		///// <summary>
		///// Returns a solved block that builds on top of this one. This exists for unit tests.
		///// </summary>
		///// <param name="to"></param>
		///// <param name="time"></param>
		///// <returns></returns>
		//Block createNextBlock(Address to,long time)
		//{
		//	return createNextBlock(to,null,time,EmptyBytes,Utils.toNanoCoins(50,0));
		//}

		///**
		// * Returns a solved block that builds on top of this one. This exists for unit tests.
		// * In this variant you can specify a public key (pubkey) for use in generating coinbase blocks.
		// */
		//Block createNextBlock(Address to, TransactionOutPoint prevOut, long time, byte[] pubKey, BigInteger coinbaseValue)
		//{
		//	Block b=new Block(Parameters);
		//	b.setDifficultyTarget(difficultyTarget);
		//	b.addCoinbaseTransaction(pubKey, coinbaseValue);

		//	if (to != null) {
		//		// Add a transaction paying 50 coins to the "to" address.
		//		Transaction t = new Transaction(Parameters);
		//		t.addOutput(new TransactionOutput(Parameters,t,Utils.toNanoCoins(50,0),to));

		//		// The input does not really need to be a valid signature, as long as it has the right general form.
		//		TransactionInput input;
		//		if(prevOut==null)
		//		{
		//			input=new TransactionInput(Parameters,t,Script.createInputScript(EMPTY_BYTES, EMPTY_BYTES));
		//			// Importantly the outpoint hash cannot be zero as that's how we detect a coinbase transaction in isolation
		//			// but it must be unique to avoid 'different' transactions looking the same.
		//			byte[] counter = new byte[32];
		//			counter[0] = (byte) txCounter++;
		//			counter[1] = 1;
		//			input.getOutpoint().setHash(new Sha256Hash(counter));
		//		}
		//		else
		//		{ input = new TransactionInput(Parameters,t,Script.createInputScript(EMPTY_BYTES,EMPTY_BYTES),prevOut); }
				
		//		t.addInput(input);
		//		b.addTransaction(t);
		//	}

		//	b.setPrevBlockHash(getHash());
		//	// Don't let timestamp go backwards
		//	if(TimeSeconds>=time)
		//	{ b.setTime(getTimeSeconds()+1); }
		//	else
		//	{ b.setTime(time); }

		//	b.solve();
		//	b.verifyHeader();

		//	return b;
		//}

		//// Visible for testing.
		//public Block createNextBlock(Address to,TransactionOutPoint prevOut)
		//{
		//	return createNextBlock(to,prevOut,Utils.now().getTime() / 1000,EmptyBytes,Utils.toNanoCoins(50,0));
		//}

		//// Visible for testing.
		//public Block createNextBlock(Address to)
		//{
		//	return createNextBlock(to, null, Utils.now().getTime() / 1000,EmptyBytes, Utils.toNanoCoins(50, 0));
		//}

		//// Visible for testing.
		//public Block createNextBlockWithCoinbase(byte[] pubKey, BigInteger coinbaseValue) {
		//	return createNextBlock(null, null, Utils.now().getTime() / 1000, pubKey, coinbaseValue);
		//}

		///**
		// * Create a block sending 50BTC as a coinbase transaction to the public key specified.
		// * This method is intended for test use only.
		// */
		//Block createNextBlockWithCoinbase(byte[] pubKey)
		//{
		//	return createNextBlock(null, null, Utils.now().getTime() / 1000, pubKey, Utils.toNanoCoins(50, 0));
		//}
		

		public override bool Equals(object other)
		{
			if(other==null)
			{ return false; }

			if(!(other is Block))
			{ return false; }
			return ReferenceEquals(this,other) || Hash.Equals(((Block)other).Hash);
		}

		public override int GetHashCode()
		{ return Hash.GetHashCode(); }
	}
}

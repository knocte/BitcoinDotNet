using System.Collections.Generic;
using BitcoinNET.Utils.Objects;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities.Encoders;

namespace BitcoinNET.BitcoinObjects.Parameters.Abstractions
{
	public abstract class NetworkParameters
	{
		// A script containing the difficulty bits and the following message:
		//"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
		public const string BitcoinGenesisBlockInputScriptSig="04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73";
		public const string BitcoinGenesisOutputScriptPubKey="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f";
		public const uint BitcoinTargetTimespan=14*24*60*60;		// 2 weeks per difficulty cycle, on average.
		public const uint BitcoinTargetSpacing=10*60;				// 10 minutes per block.
		public static readonly Coin BitcoinMaxMoney=Coin.FromCoins(21000000);

		
		/// <summary>
		/// The protocol version this library implements. A value of 31800 means 0.3.18.00.
		/// </summary>
		public uint ProtocolVersion=31800;

		/// <summary>
		/// How much time in seconds is supposed to pass between "interval" blocks. If the actual elapsed time is
		/// significantly different from this value, the network difficulty formula will produce a different value. Both
		/// test and production Bitcoin networks use 2 weeks (1209600 seconds).
		/// </summary>
		public abstract uint TargetTimespan { get; }
		public abstract uint TargetSpacing { get; }
		public uint Interval { get { return TargetTimespan/TargetSpacing; } }

		/// <summary>
		/// The maximum money to be generated
		/// </summary>
		public abstract Coin MaxMoney { get; }

		//TODO: Seed nodes and checkpoint values should be here as well.


		public abstract string GenesisBlockInputScriptSig { get; }
		public abstract string GenesisOutputScriptPubKey { get; }

		/// <summary>
		/// Genesis block for this chain.
		/// </summary>
		/// <remarks>
		/// The first block in every chain is a well known constant shared between all Bitcoin implementations. For a
		/// block to be valid, it must be eventually possible to work backwards to the genesis block by following the
		/// prevBlockHash pointers in the block headers.<p/>
		/// The genesis blocks for both test and prod networks contain the timestamp of when they were created,
		/// and a message in the coinbase transaction. It says, <i>"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"</i>.
		/// </remarks>
		public abstract Block GenesisBlock { get; }

		/// <summary>
		/// What the easiest allowable proof of work should be.
		/// </summary>
		public abstract BigInteger ProofOfWorkLimit { get; }

		/// <summary>
		/// Default TCP port on which to connect to nodes.
		/// </summary>
		public abstract int Port { get; }

		/// <summary>
		/// The header bytes that identify the start of a packet on this network.
		/// </summary>
		public abstract uint PacketMagic { get; }

		/// <summary>
		/// First byte of a base58 encoded address. See <see cref="Address"/>
		/// </summary>
		public abstract int AddressHeader { get; }

		/// <summary>
		/// First byte of a base58 encoded dumped private key. See <see cref="DumpedPrivateKey"/>.
		/// </summary>
		public abstract int DumpedPrivateKeyHeader { get; }

	 //   /**
	 //	* The key used to sign {@link AlertMessage}s. You can use {@link ECKey#verify(byte[], byte[], byte[])} to verify
	 //	* signatures using it.
	 //	*/
	 //   public byte[] alertSigningKey;

	 //   /**
	 //* See getId(). This may be null for old deserialized wallets. In that case we derive it heuristically
	 //* by looking at the port number.
	 //*/
	 //   private String id;

		/// <summary>
		/// The depth of blocks required for a coinbase transaction to be spendable.
		/// </summary>
		public abstract uint SpendableCoinbaseDepth { get; }

		/// <summary>
		/// Returns the number of blocks between subsidy decreases
		/// </summary>
		public abstract uint SubsidyDecreaseBlockCount { get; }

		/// <summary>
		/// If we are running in testnet-in-a-box mode, we allow connections to nodes with 0 non-genesis blocks
		/// </summary>
		public abstract bool AllowEmptyPeerChains { get; }

		/// <summary>
		/// The version codes that prefix addresses which are acceptable on this network.
		/// Although Satoshi intended these to be used for "versioning", in fact they are today used to discriminate what kind of data is contained in the address and to prevent accidentally sending coins across chains which would destroy them.
		/// </summary>
		public abstract int[] AcceptableAddressCodes { get; }

		///**
		// * Blocks with a timestamp after this should enforce BIP 16, aka "Pay to script hash". This BIP changed the
		// * network rules in a soft-forking manner, that is, blocks that don't follow the rules are accepted but not
		// * mined upon and thus will be quickly re-orged out as long as the majority are enforcing the rule.
		// */
		//public abstract int BIP16_ENFORCE_TIME = 1333238400;

		/// <summary>
		/// Block checkpoints are a safety mechanism that hard-codes the hashes of blocks at particular heights.
		/// Re-orgs beyond this point will never be accepted. This field should be accessed using PassesCheckpoint and IsCheckpoint
		/// </summary>
		protected Dictionary<int,Sha256Hash> Checkpoints=new Dictionary<int,Sha256Hash>();


	//public boolean equals(Object other) {
	//	if (!(other instanceof NetworkParameters)) return false;
	//	NetworkParameters o = (NetworkParameters) other;
	//	return o.getId().equals(getId());
	//}




		public Block CreateGenesis(NetworkParameters n)
		{
			Block genesisBlock=new Block(n);
			Transaction transaction=new Transaction(n);
			transaction.AddInput(
				new TransactionInput(n,transaction,Hex.Decode(n.GenesisBlockInputScriptSig))
			);


			ByteArrayOutputStream scriptPubKeyBytes = new ByteArrayOutputStream();
			Script.writeBytes(scriptPubKeyBytes,Hex.Decode(n.GenesisOutputScriptPubKey));
			scriptPubKeyBytes.write(Script.OP_CHECKSIG);
			t.addOutput(new TransactionOutput(n,transaction,Coin.FromCoins(50).Nanocoins,scriptPubKeyBytes.toByteArray()));

			genesisBlock.addTransaction(transaction);
			return genesisBlock;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="height"></param>
		/// <param name="hash"></param>
		/// <returns>True if the block height is either not a checkpoint, or is a checkpoint and the hash matches.</returns>
		public bool PassesCheckpoint(int height,Sha256Hash hash)
		{
			if(hash!=null)
			{
				Sha256Hash checkpointHash;
				if(Checkpoints.TryGetValue(height,out checkpointHash))
				{ return checkpointHash.Equals(hash); }
			}
			return true;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="height"></param>
		/// <returns>True if the given height has a recorded checkpoint.</returns>
		public bool IsCheckpoint(int height)
		{ return Checkpoints.ContainsKey(height); }

		/// <summary>
		/// A utility method that calculates how much new Bitcoin would be created by the block at the given height.
		/// The inflation of Bitcoin is predictable and drops roughly every 4 years (210,000 blocks).
		/// At the dawn of the system it was 50 coins per block, in late 2012 it went to 25 coins per block, and so on.
		/// The size of a coinbase transaction is inflation plus fees.
		/// The half-life is controlled by SubsidyDecreaseBlockCount
		/// </summary>
		/// <param name="height"></param>
		/// <returns></returns>
		public BigInteger GetBlockInflation(int height)
		{ return Coin.FromCoins(50).Nanocoins.ShiftRight((int)(height/SubsidyDecreaseBlockCount)); }
	}
}

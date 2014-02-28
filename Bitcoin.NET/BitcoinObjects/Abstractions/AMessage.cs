using System;
using System.IO;
using System.Text;
using BitcoinNET.BitcoinObjects.Exceptions;
using BitcoinNET.BitcoinObjects.Parameters.Abstractions;
using BitcoinNET.Utils.Extensions;
using BitcoinNET.Utils.Objects;

namespace BitcoinNET.BitcoinObjects.Abstractions
{
	/// <summary>
	/// A Message is a data structure that can be serialized/deserialized using both the BitCoin proprietary serialization
	/// format and built-in Java object serialization. Specific types of messages that are used both in the block chain,
	/// and on the wire, are derived from this class.
	/// </summary>
	/// <remarks>
	/// This class is not useful for library users. If you want to talk to the network see the <see cref="Peer"/> class.
	/// </remarks>
	[Serializable]
	public abstract class AMessage
	{
		public const int MaxSize=0x02000000;
		public const int UnknownLength=int.MinValue;
		public const bool SelfCheck=false;		//Useful to ensure serialize/deserialize are consistent with each other.

		
		[NonSerialized]protected int Offset;	// The offset is how many bytes into the provided byte array this message starts at.
		[NonSerialized]protected int Cursor;	// The cursor keeps track of where we are in the byte array as we parse it. Note that it's relative to the start of the array NOT the start of the message.
		[NonSerialized]protected int Length=UnknownLength;
		[NonSerialized]protected byte[] Bytes;	// The raw message bytes themselves.
		
		[NonSerialized]protected bool Parsed=false;
		[NonSerialized]protected bool ParseLazy;
		[NonSerialized]protected bool ParseRetain;
		[NonSerialized]protected uint ProtocolVersion;
		
		[NonSerialized]private byte[] checksum;
		protected byte[] Checksum				//Should only used by BitcoinSerializer for cached checksum
		{
			get { return checksum; }
			set
			{
				if(value.Length!=4)
				{ throw new ArgumentException(string.Format("Checksum length must be 4 bytes, actual length: {0}",value.Length)); }
				checksum=value;
			}
		}

		public bool HasMoreBytes { get { return Cursor<Bytes.Length; } }

		/// This should be overridden to extract correct message size in the case of lazy parsing.  Until this method is implemented in a subclass of ChildMessage lazy parsing may have no effect.
		/// This default implementation is a safe fall back that will ensure it returns a correct value by parsing the message.
		public int MessageSize
		{
			get
			{
				if(Length!=UnknownLength)
				{ return Length; }

				EnsureParsed();
				return Length;
			}
		}

		public virtual Sha256Hash Hash { get { return null; } }	//This method is a NOP for all classes except Block and Transaction.  It is only declared in Message so BitcoinSerializer can avoid 2 instanceof checks + a casting.

		protected readonly NetworkParameters Parameters;	// This will be saved by subclasses that implement Serializable.


		protected AMessage(NetworkParameters parameters)
		{
			Parameters=parameters;
			Parsed=true;
			ParseLazy=false;
			ParseRetain=false;
		}

		/// <see cref="AMessage(NetworkParameters,byte[],int,uint,bool,bool,int)"/>
		protected AMessage(NetworkParameters parameters,byte[] msg,int offset,uint protocolVersion):this(parameters,msg,offset,protocolVersion,false,false,UnknownLength)
		{ }

		/// <see cref="AMessage(NetworkParameters,byte[],int,uint,bool,bool,int)"/>
		protected AMessage(NetworkParameters parameters,byte[] msg,int offset):this(parameters,msg,offset,NetworkParameters.ProtocolVersion,false,false,UnknownLength)
		{ }

		/// <see cref="AMessage(NetworkParameters,byte[],int,uint,bool,bool,int)"/>
		protected AMessage(NetworkParameters parameters,byte[] msg,int offset,bool parseLazy,bool parseRetain,int length):this(parameters,msg,offset,NetworkParameters.ProtocolVersion,parseLazy,parseRetain,length)
		{ }

		/// <summary>
		/// <exception cref="ProtocolException"/>
		/// </summary>
		/// <param name="parameters">NetworkParameters object</param>
		/// <param name="msg">Bitcoin protocol formatted byte array containing message content</param>
		/// <param name="offset">The location of the first msg byte within the array</param>
		/// <param name="protocolVersion">Bitcoin protocol version</param>
		/// <param name="parseLazy">Whether to perform a full parse immediately or delay until a read is requested.</param>
		/// <param name="parseRetain">
		/// Whether to retain the backing byte array for quick reserialization.
		/// If true and the backing byte array is invalidated due to modification of a field then the cached bytes may be repopulated and retained if the message is serialized again in the future.
		/// </param>
		/// <param name="length">The length of message if known.  Usually this is provided when deserializing of the wire as the length will be provided as part of the header. If unknown then set to Message.UnknownLength</param>
		protected AMessage(NetworkParameters parameters,byte[] msg,int offset,uint protocolVersion,bool parseLazy,bool parseRetain,int length)
		{
			ParseLazy=parseLazy;
			ParseRetain=parseRetain;
			ProtocolVersion=protocolVersion;
			Parameters=parameters;
			Bytes=msg;
			Cursor=Offset=offset;
			Length=length;
			
			if(parseLazy)
			{ ParseLite(); }
			else
			{
				ParseLite();
				Parse();
				Parsed=true;
			}
           
			#if SelfCheck
			if(SelfCheck)
			{ selfCheck(msg,offset); }
			#endif
			
			if(!parseRetain && Parsed)
			{ Bytes=null; }
		}
		
		#if SelfCheck
		private void selfCheck(byte[] msg,int offset)
		{
			if(GetType() != typeof(VersionMessage))
            {
                var msgbytes=new byte[Cursor - offset];
                Array.Copy(msg, offset, msgbytes, 0, Cursor - offset);
                var reserialized = BitcoinSerialize();
                if (!reserialized.SequenceEqual(msgbytes))
				{ throw new Exception(string.Format("Serialization is wrong: \r\n{0} vs \r\n{1}",Utils.BytesToHexString(reserialized),Utils.BytesToHexString(msgbytes))); }
            }
		}
		#endif

		/// <summary>
		/// Perform the most minimal parse possible to calculate the length of the message.
		/// This is only required for subclasses of ChildClass as root level messages will have their length passed into the constructor.
		/// Implementations should adhere to the following contract: If parseLazy = true the 'length' field must be set before returning.
		/// If parseLazy = false the length field must be set either within the parseLite() method OR the parse() method.
		/// The overriding requirement is that length must be set to non UnknownLength value by the time the constructor exits.
		/// <exception cref="ProtocolException"/>
		/// </summary>
		protected abstract void ParseLite();

		/// 
		/// <summary>
		/// These methods handle the serialization/deserialization using the custom BitCoin protocol.
		/// It's somewhat painful to work with in Java, so some of these objects support a second serialization mechanism - the standard Java serialization system.
		/// This is used when things are serialized to the wallet.
		/// <exception cref="ProtocolException"/>
		/// </summary>
		protected abstract void Parse();


		/// <summary>
		/// In lazy parsing mode access to getters and setters may throw an unchecked LazyParseException.
		/// If guaranteed safe access is required this method will force parsing to occur immediately thus ensuring LazyParseExeption will never be thrown from this Message.
		/// If the Message contains child messages (e.g. a Block containing Transaction messages) this will not force child messages to parse.
		/// This could be overidden for Transaction and it's child classes to ensure the entire tree of Message objects is parsed.
		/// <exception cref="ProtocolException"/>
		/// </summary>
		public virtual void EnsureParsed()
		{
			if(!Parsed && Bytes!=null)
			{
				lock(this)
				{
					if(!Parsed && Bytes!=null)
					{
						Parse();
						Parsed=true;
						if(!ParseRetain)
						{ Bytes = null; }
					}
				}
			}
		}
		
		protected void AdjustLength(int newArraySize,int adjustment)
		{
			if(Length==UnknownLength)
			{ return; }
			
			// Our own length is now unknown if we have an unknown length adjustment.
			if(adjustment==UnknownLength)
			{
				Length=UnknownLength;
				return;
			}
			
			Length+=adjustment;
			
			// Check if we will need more bytes to encode the length prefix.
			if(newArraySize==1)
			{ Length++; }  // The assumption here is we never call adjustLength with the same arraySize as before.
			else if(newArraySize!=0)
			{ Length+=VarInt.SizeInBytesOf((ulong)newArraySize)-VarInt.SizeInBytesOf((ulong)(newArraySize-1)); }
		}


		/// <summary>
		/// Serialize this message to a byte array that conforms to the bitcoin wire protocol.
		/// This method may return the original byte array used to construct this message if the following conditions are met:
		/// <ol>
		///		<li>1) The message was parsed from a byte array with parseRetain = true</li>
		///		<li>2) The message has not been modified</li>
		///		<li>3) The array had an offset of 0 and no surplus bytes</li>
		/// </ol>
		/// 
		/// If condition 3 is not met then an copy of the relevant portion of the array will be returned.
		/// Otherwise a full serialize will occur. For this reason you should only use this API if you can guarantee you will treat the resulting array as read only.
		/// </summary>
		/// <returns>A byte array owned by this object, do NOT mutate it.</returns>
		public byte[] BitcoinSerializeUnsafe()
		{
			// 1st attempt to use a cached array.
			if(Bytes!=null && Length!=UnknownLength)
			{
				if(Offset==0 && Length==Bytes.Length)
				{
					// Cached byte array is the entire message with no extras so we can return as is and avoid an array copy.
					return Bytes;
				}

				byte[] buffer=new byte[Length];
				Array.Copy(Bytes,Offset,buffer,0,Length);
				return buffer;
			}
			
			// No cached array available so serialize parts by stream.
			byte[] serializeBytes=BitcoinSerialize();
			
			if(ParseRetain)
			{
				// A free set of steak knives!
				// If there happens to be a call to this method we gain an opportunity to recache the byte array and in this case it contains no bytes from parent messages.
				// This give a dual benefit.  Releasing references to the larger byte array so that it it is more likely to be GC'd and preventing double serializations.
				//E.g. calculating merkle root calls this method.  It is will frequently happen prior to serializing the block which means another call to bitcoinSerialize is coming.
				//If we didn't recache then internal serialization would occur a 2nd time and every subsequent time the message is serialized.
				Bytes=serializeBytes;
				Cursor=Cursor-Offset;
				Offset=0;
				Length=Bytes.Length;
				return Bytes;
			}

			// Record length. If this Message wasn't parsed from a byte stream it won't have length field
			// set (except for static length message types).  Setting it makes future streaming more efficient
			// because we can preallocate the ByteArrayOutputStream buffer and avoid resizing.
			Length=serializeBytes.Length;
			return serializeBytes;
		}
		public virtual byte[] BitcoinSerialize()
		{
			using(MemoryStream stream=new MemoryStream())
            {
                BitcoinSerializeToStream(stream);
                return stream.ToArray();
            }
		}

		/// <summary>
		/// Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
		/// </summary>
		/// <param name="stream"></param>
		public abstract void BitcoinSerializeToStream(Stream stream);

		

		public int ReadInt32()
		{
			int u=Bytes.ReadInt32(Cursor);
			Cursor+=4;
			return u;
		}

		public uint ReadUint32()
		{
			uint u=Bytes.ReadUint32(Cursor);
			Cursor+=4;
			return u;
		}
		
		public long ReadInt64()
		{
			long u=Bytes.ReadInt64(Cursor);
			Cursor+=8;
			return u;
		}
		
		public ulong ReadUint64()
		{
			ulong u=Bytes.ReadUint64(Cursor);
			Cursor+=8;
			return u;
		}

		public VarInt ReadVarInt()
		{ return ReadVarInt(0); }
		public VarInt ReadVarInt(int offset)
		{
			VarInt varint=new VarInt(Bytes,Cursor+offset);
			Cursor+=offset+varint.SizeInBytes;
			return varint;
		}
		
		public byte[] ReadBytes(int length)
		{
			byte[] b=new byte[length];
            Array.Copy(Bytes,Cursor,b,0,length);
            Cursor+=length;
            return b;
		}

		public byte[] ReadByteArray()
		{
			VarInt len=ReadVarInt();
			return ReadBytes((int)len.Value);
		}
		
		public Sha256Hash ReadHash()
		{
			byte[] hash=new byte[32];
			Array.Copy(Bytes,Cursor,hash,0,32);
			
			// We have to flip it around, as it's been read off the wire in little endian.
			// Not the most efficient way to do this but the clearest.
			Array.Reverse(hash);
            Cursor+=32;
            return new Sha256Hash(hash);
		}
		
		public string ReadString()
		{
			var varInt=new VarInt(Bytes,Cursor);
            if(varInt.Value==0)
            {
                Cursor+=1;
                return string.Empty;
            }

            Cursor+=varInt.SizeInBytes;
            return Encoding.UTF8.GetString(Bytes,Cursor,(int)varInt.Value);
		}
	}
}

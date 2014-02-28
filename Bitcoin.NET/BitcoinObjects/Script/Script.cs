using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BitcoinNET.BitcoinObjects.Exceptions;
using BitcoinNET.BitcoinObjects.Parameters.Abstractions;
using BitcoinNET.Utils;
using BitcoinNET.Utils.Extensions;
using BitcoinNET.Utils.Objects;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

namespace BitcoinNET.BitcoinObjects.Script
{
	/// <summary>
	/// Instructions for redeeming a payment.
	/// Bitcoin transactions don't specify what they do directly.
	/// Instead <a href="https://en.bitcoin.it/wiki/Script">a small binary stack language</a> is used to define programs that when evaluated return whether the transaction "accepts" or rejects the other transactions connected to it.
	/// In SPV mode, scripts are not run, because that would require all transactions to be available and lightweight clients don't have that data.
	/// In full mode, this class is used to run the interpreted language. It also has static methods for building scripts.
	/// </summary>
	public class Script
	{
		// Some constants used for decoding the scripts, copied from the reference client
		// push value
		public const int OP_0=0x00;
		public const int OP_FALSE=OP_0;
		public const int OP_PUSHDATA1=0x4c;
		public const int OP_PUSHDATA2=0x4d;
		public const int OP_PUSHDATA4=0x4e;
		public const int OP_1NEGATE=0x4f;
		public const int OP_RESERVED=0x50;
		public const int OP_1=0x51;
		public const int OP_TRUE=OP_1;
		public const int OP_2=0x52;
		public const int OP_3=0x53;
		public const int OP_4=0x54;
		public const int OP_5=0x55;
		public const int OP_6=0x56;
		public const int OP_7=0x57;
		public const int OP_8=0x58;
		public const int OP_9=0x59;
		public const int OP_10=0x5a;
		public const int OP_11=0x5b;
		public const int OP_12=0x5c;
		public const int OP_13=0x5d;
		public const int OP_14=0x5e;
		public const int OP_15=0x5f;
		public const int OP_16=0x60;

		// control
		public const int OP_NOP=0x61;
		public const int OP_VER=0x62;
		public const int OP_IF=0x63;
		public const int OP_NOTIF=0x64;
		public const int OP_VERIF=0x65;
		public const int OP_VERNOTIF=0x66;
		public const int OP_ELSE=0x67;
		public const int OP_ENDIF=0x68;
		public const int OP_VERIFY=0x69;
		public const int OP_RETURN=0x6a;

		// stack ops
		public const int OP_TOALTSTACK=0x6b;
		public const int OP_FROMALTSTACK=0x6c;
		public const int OP_2DROP=0x6d;
		public const int OP_2DUP=0x6e;
		public const int OP_3DUP=0x6f;
		public const int OP_2OVER=0x70;
		public const int OP_2ROT=0x71;
		public const int OP_2SWAP=0x72;
		public const int OP_IFDUP=0x73;
		public const int OP_DEPTH=0x74;
		public const int OP_DROP=0x75;
		public const int OP_DUP=0x76;
		public const int OP_NIP=0x77;
		public const int OP_OVER=0x78;
		public const int OP_PICK=0x79;
		public const int OP_ROLL=0x7a;
		public const int OP_ROT=0x7b;
		public const int OP_SWAP=0x7c;
		public const int OP_TUCK=0x7d;

		// splice ops
		public const int OP_CAT=0x7e;
		public const int OP_SUBSTR=0x7f;
		public const int OP_LEFT=0x80;
		public const int OP_RIGHT=0x81;
		public const int OP_SIZE=0x82;

		// bit logic
		public const int OP_INVERT=0x83;
		public const int OP_AND=0x84;
		public const int OP_OR=0x85;
		public const int OP_XOR=0x86;
		public const int OP_EQUAL=0x87;
		public const int OP_EQUALVERIFY=0x88;
		public const int OP_RESERVED1=0x89;
		public const int OP_RESERVED2=0x8a;

		// numeric
		public const int OP_1ADD=0x8b;
		public const int OP_1SUB=0x8c;
		public const int OP_2MUL=0x8d;
		public const int OP_2DIV=0x8e;
		public const int OP_NEGATE=0x8f;
		public const int OP_ABS=0x90;
		public const int OP_NOT=0x91;
		public const int OP_0NOTEQUAL=0x92;

		public const int OP_ADD=0x93;
		public const int OP_SUB=0x94;
		public const int OP_MUL=0x95;
		public const int OP_DIV=0x96;
		public const int OP_MOD=0x97;
		public const int OP_LSHIFT=0x98;
		public const int OP_RSHIFT=0x99;

		public const int OP_BOOLAND=0x9a;
		public const int OP_BOOLOR=0x9b;
		public const int OP_NUMEQUAL=0x9c;
		public const int OP_NUMEQUALVERIFY=0x9d;
		public const int OP_NUMNOTEQUAL=0x9e;
		public const int OP_LESSTHAN=0x9f;
		public const int OP_GREATERTHAN=0xa0;
		public const int OP_LESSTHANOREQUAL=0xa1;
		public const int OP_GREATERTHANOREQUAL=0xa2;
		public const int OP_MIN=0xa3;
		public const int OP_MAX=0xa4;

		public const int OP_WITHIN=0xa5;

		// crypto
		public const int OP_RIPEMD160=0xa6;
		public const int OP_SHA1=0xa7;
		public const int OP_SHA256=0xa8;
		public const int OP_HASH160=0xa9;
		public const int OP_HASH256=0xaa;
		public const int OP_CODESEPARATOR=0xab;
		public const int OP_CHECKSIG=0xac;
		public const int OP_CHECKSIGVERIFY=0xad;
		public const int OP_CHECKMULTISIG=0xae;
		public const int OP_CHECKMULTISIGVERIFY=0xaf;

		// expansion
		public const int OP_NOP1=0xb0;
		public const int OP_NOP2=0xb1;
		public const int OP_NOP3=0xb2;
		public const int OP_NOP4=0xb3;
		public const int OP_NOP5=0xb4;
		public const int OP_NOP6=0xb5;
		public const int OP_NOP7=0xb6;
		public const int OP_NOP8=0xb7;
		public const int OP_NOP9=0xb8;
		public const int OP_NOP10=0xb9;

		public const int OP_INVALIDOPCODE=0xff;

		byte[] program;
		private int cursor;

		// The program is a set of byte[]s where each element is either [opcode] or [data, data, data ...]
		List<ScriptChunk> chunks;
		private readonly NetworkParameters parameters;
    
		/// <summary>
		/// Only for internal use
		/// </summary>
		private Script()
		{ parameters=null; }

		/// <summary>
		/// Construct a Script using the given network parameters and a range of the programBytes array
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="parameters">Network parameters.</param>
		/// <param name="programBytes">Array of program bytes from a transaction.</param>
		/// <param name="offset">How many bytes into programBytes to start reading from.</param>
		/// <param name="length">How many bytes to read.</param>
		public Script(NetworkParameters parameters,byte[] programBytes,int offset,int length)
		{
			this.parameters=parameters;
			parse(programBytes,offset,length);
		}

		/// <summary>
		/// Returns the program opcodes as a string, for example "[1234] DUP HAHS160"
		/// </summary>
		/// <returns></returns>
		public override string ToString()
		{
			StringBuilder builder=new StringBuilder();
			
			foreach(ScriptChunk chunk in chunks)
			{
				if(chunk.IsOpCode)
				{
					builder.Append(getOpCodeName(chunk.Data[0]));
					builder.Append(" ");
				}
				else
				{
					// Data chunk
					builder.Append("[");
					builder.Append(bytesToHexString(chunk.Data));
					builder.Append("] ");
				}
			}

			return builder.ToString();
		}
    
		/// <summary>
		/// Converts the given OpCode into a string (eg "0", "PUSHDATA", or "NON_OP(10)")
		/// </summary>
		/// <param name="opCode"></param>
		/// <returns></returns>
		public static string getOpCodeName(byte opCode)
		{
			int opcode=opCode & 0xff;

			switch (opcode)
			{
				case OP_0:
					return "0";
				case OP_PUSHDATA1:
					return "PUSHDATA1";
				case OP_PUSHDATA2:
					return "PUSHDATA1";
				case OP_PUSHDATA4:
					return "PUSHDATA4";
				case OP_1NEGATE:
					return "1NEGATE";
				case OP_RESERVED:
					return "RESERVED";
				case OP_1:
					return "1";
				case OP_2:
					return "2";
				case OP_3:
					return "3";
				case OP_4:
					return "4";
				case OP_5:
					return "5";
				case OP_6:
					return "6";
				case OP_7:
					return "7";
				case OP_8:
					return "8";
				case OP_9:
					return "9";
				case OP_10:
					return "10";
				case OP_11:
					return "11";
				case OP_12:
					return "12";
				case OP_13:
					return "13";
				case OP_14:
					return "14";
				case OP_15:
					return "15";
				case OP_16:
					return "16";
				case OP_NOP:
					return "NOP";
				case OP_VER:
					return "VER";
				case OP_IF:
					return "IF";
				case OP_NOTIF:
					return "NOTIF";
				case OP_VERIF:
					return "VERIF";
				case OP_VERNOTIF:
					return "VERNOTIF";
				case OP_ELSE:
					return "ELSE";
				case OP_ENDIF:
					return "ENDIF";
				case OP_VERIFY:
					return "VERIFY";
				case OP_RETURN:
					return "RETURN";
				case OP_TOALTSTACK:
					return "TOALTSTACK";
				case OP_FROMALTSTACK:
					return "FROMALTSTACK";
				case OP_2DROP:
					return "2DROP";
				case OP_2DUP:
					return "2DUP";
				case OP_3DUP:
					return "3DUP";
				case OP_2OVER:
					return "2OVER";
				case OP_2ROT:
					return "2ROT";
				case OP_2SWAP:
					return "2SWAP";
				case OP_IFDUP:
					return "IFDUP";
				case OP_DEPTH:
					return "DEPTH";
				case OP_DROP:
					return "DROP";
				case OP_DUP:
					return "DUP";
				case OP_NIP:
					return "NIP";
				case OP_OVER:
					return "OVER";
				case OP_PICK:
					return "PICK";
				case OP_ROLL:
					return "ROLL";
				case OP_ROT:
					return "ROT";
				case OP_SWAP:
					return "SWAP";
				case OP_TUCK:
					return "TUCK";
				case OP_CAT:
					return "CAT";
				case OP_SUBSTR:
					return "SUBSTR";
				case OP_LEFT:
					return "LEFT";
				case OP_RIGHT:
					return "RIGHT";
				case OP_SIZE:
					return "SIZE";
				case OP_INVERT:
					return "INVERT";
				case OP_AND:
					return "AND";
				case OP_OR:
					return "OR";
				case OP_XOR:
					return "XOR";
				case OP_EQUAL:
					return "EQUAL";
				case OP_EQUALVERIFY:
					return "EQUALVERIFY";
				case OP_RESERVED1:
					return "RESERVED1";
				case OP_RESERVED2:
					return "RESERVED2";
				case OP_1ADD:
					return "1ADD";
				case OP_1SUB:
					return "1SUB";
				case OP_2MUL:
					return "2MUL";
				case OP_2DIV:
					return "2DIV";
				case OP_NEGATE:
					return "NEGATE";
				case OP_ABS:
					return "ABS";
				case OP_NOT:
					return "NOT";
				case OP_0NOTEQUAL:
					return "0NOTEQUAL";
				case OP_ADD:
					return "ADD";
				case OP_SUB:
					return "SUB";
				case OP_MUL:
					return "MUL";
				case OP_DIV:
					return "DIV";
				case OP_MOD:
					return "MOD";
				case OP_LSHIFT:
					return "LSHIFT";
				case OP_RSHIFT:
					return "RSHIFT";
				case OP_BOOLAND:
					return "BOOLAND";
				case OP_BOOLOR:
					return "BOOLOR";
				case OP_NUMEQUAL:
					return "NUMEQUAL";
				case OP_NUMEQUALVERIFY:
					return "NUMEQUALVERIFY";
				case OP_NUMNOTEQUAL:
					return "NUMNOTEQUAL";
				case OP_LESSTHAN:
					return "LESSTHAN";
				case OP_GREATERTHAN:
					return "GREATERTHAN";
				case OP_LESSTHANOREQUAL:
					return "LESSTHANOREQUAL";
				case OP_GREATERTHANOREQUAL:
					return "GREATERTHANOREQUAL";
				case OP_MIN:
					return "MIN";
				case OP_MAX:
					return "MAX";
				case OP_WITHIN:
					return "WITHIN";
				case OP_RIPEMD160:
					return "RIPEMD160";
				case OP_SHA1:
					return "SHA1";
				case OP_SHA256:
					return "SHA256";
				case OP_HASH160:
					return "HASH160";
				case OP_HASH256:
					return "HASH256";
				case OP_CODESEPARATOR:
					return "CODESEPARATOR";
				case OP_CHECKSIG:
					return "CHECKSIG";
				case OP_CHECKSIGVERIFY:
					return "CHECKSIGVERIFY";
				case OP_CHECKMULTISIG:
					return "CHECKMULTISIG";
				case OP_CHECKMULTISIGVERIFY:
					return "CHECKMULTISIGVERIFY";
				case OP_NOP1:
					return "NOP1";
				case OP_NOP2:
					return "NOP2";
				case OP_NOP3:
					return "NOP3";
				case OP_NOP4:
					return "NOP4";
				case OP_NOP5:
					return "NOP5";
				case OP_NOP6:
					return "NOP6";
				case OP_NOP7:
					return "NOP7";
				case OP_NOP8:
					return "NOP8";
				case OP_NOP9:
					return "NOP9";
				case OP_NOP10:
					return "NOP10";
				default:
					return "NON_OP("+opcode+")";
			}
		}

		/// <summary>
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="len"></param>
		/// <returns></returns>
		private byte[] getData(int len)
		{
			if(len>program.Length-cursor || len<0)
			{ throw new ScriptException("Failed reading of "+len+" bytes"); }
			
			byte[] buffer=program.Duplicate(cursor,len);
			cursor+=len;

			return buffer;
		}

		private int readByte()
		{
			if(cursor>=program.Length)
			{ throw new ScriptException("Attempted to read outside of script boundaries"); }

			return 0xFF & program[cursor++];
		}

		/// <summary>
		/// To run a script, first we parse it which breaks it up into chunks representing pushes of data or logical opcodes. Then we can run the parsed chunks.
		/// The reason for this split, instead of just interpreting directly, is to make it easier to reach into a programs structure and pull out bits of data without having to run it.
		/// This is necessary to render the to/from addresses of transactions in a user interface.
		/// The official client does something similar.
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="programBytes"></param>
		/// <param name="offset"></param>
		/// <param name="length"></param>
		private void parse(byte[] programBytes, int offset, int length)
		{
			// TODO: this is inefficient
			program=programBytes.Duplicate(offset,length);

			offset=0;
			chunks=new List<ScriptChunk>(10);  // Arbitrary choice of initial size.
			cursor=offset;

			while(cursor<offset+length)
			{
				int startLocationInProgram=cursor-offset;
				int opcode=readByte();

				if(opcode>=0 && opcode<OP_PUSHDATA1)
				{
					// Read some bytes of data, where how many is the opcode value itself.
					chunks.Add(new ScriptChunk(false,getData(opcode),startLocationInProgram));  // opcode == len here.
				}
				else if(opcode==OP_PUSHDATA1)
				{
					int len=readByte();
					chunks.Add(new ScriptChunk(false,getData(len),startLocationInProgram));
				}
				else if(opcode==OP_PUSHDATA2)
				{
					// Read a short, then read that many bytes of data.
					int len=readByte() | (readByte()<<8);
					chunks.Add(new ScriptChunk(false,getData(len),startLocationInProgram));
				}
				else if(opcode==OP_PUSHDATA4)
				{
					// Read a uint32, then read that many bytes of data.
					// Though this is allowed, because its value cannot be > 520, it should never actually be used
					long len=readByte() | (readByte()<<8) | (readByte()<<16) | (readByte()<<24);
					chunks.Add(new ScriptChunk(false,getData((int)len),startLocationInProgram));
				}
				else
				{ chunks.Add(new ScriptChunk(true,new[]{ (byte)opcode },startLocationInProgram)); }
			}
		}

		 
		/// <summary>
		/// Returns true if this script is of the form sig OP_CHECKSIG.
		/// This form was originally intended for transactions where the peers talked to each other directly via TCP/IP,
		/// but has fallen out of favor with time due to that mode of operation being susceptible to man-in-the-middle attacks.
		/// It is still used in coinbase outputs and can be useful more exotic types of transaction, but today most payments are to addresses.
		/// </summary>
		/// <returns></returns>
		public bool isSentToRawPubKey()
		{
			if(chunks.Count!=2)
			{ return false; }
			return chunks[1].EqualsOpCode(OP_CHECKSIG) &&
				  !chunks[0].IsOpCode &&
				   chunks[0].Data.Length>1;
		}

		/// <summary>
		/// Returns true if this script is of the form DUP HASH160 pubkey hash EQUALVERIFY CHECKSIG, ie, payment to an address like 1VayNert3x1KzbpzMGt2qdqrAThiRovi8.
		/// This form was originally intended for the case where you wish to send somebody money with a written code because their node is offline,
		/// but over time has become the standard way to make payments due to the short and recognizable base58 form addresses come in.
		/// </summary>
		/// <returns></returns>
		public bool isSentToAddress()
		{
			if(chunks.Count!=5)
			{ return false; }

			return chunks[0].EqualsOpCode(OP_DUP) &&
				   chunks[1].EqualsOpCode(OP_HASH160) &&
				   chunks[2].Data.Length==Address.Length &&
				   chunks[3].EqualsOpCode(OP_EQUALVERIFY) &&
				   chunks[4].EqualsOpCode(OP_CHECKSIG);
		}

		/// <summary>
		/// If a program matches the standard template DUP HASH160 pubkey hash EQUALVERIFY CHECKSIG then this function retrieves the third element, otherwise it throws a ScriptException.
		/// This is useful for fetching the destination address of a transaction.
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <returns></returns>
		public byte[] getPubKeyHash()
		{
			if(!isSentToAddress())
			{ throw new ScriptException("Script not in the standard scriptPubKey form"); }
			
			// Otherwise, the third element is the hash of the public key, ie the bitcoin address.
			return chunks[2].Data;
		}

		/// <summary>
		/// Returns the public key in this script.
		/// If a script contains two constants and nothing else, it is assumed to be a scriptSig (input) for a pay-to-address output and the second constant is returned (the first is the signature).
		/// If a script contains a constant and an OP_CHECKSIG opcode, the constant is returned as it is assumed to be a direct pay-to-key scriptPubKey (output) and the first constant is the public key.
		/// <exception cref="ScriptException">if the script is none of the named forms</exception>
		/// </summary>
		/// <returns></returns>
		public byte[] getPubKey()
		{
			if(chunks.Count!=2)
			{ throw new ScriptException("Script not of right size, expecting 2 but got "+chunks.Count); }

			// If we have two large constants assume the input to a pay-to-address output.
			if(chunks[0].Data.Length>2 && chunks[1].Data.Length>2)
			{ return chunks[1].Data; }
			
			// A large constant followed by an OP_CHECKSIG is the key.
			if(chunks[1].Data.Length==1 && chunks[1].EqualsOpCode(OP_CHECKSIG) && chunks[0].Data.Length>2)
			{ return chunks[0].Data; }

			throw new ScriptException("Script did not match expected form: "+ToString());
		}

		/// <summary>
		/// Convenience wrapper around getPubKey. Only works for scriptSigs
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <returns></returns>
		public Address getFromAddress()
		{
			return new Address(parameters,getPubKey().Sha256Hash160());
		}

		/// <summary>
		/// Gets the destination address from this script, if it's in the required form (see <seealso cref="getPubKey"/>).
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <returns></returns>
		public Address getToAddress()
		{
			return new Address(parameters,getPubKeyHash());
		}

		////////////////////// Interface for writing scripts from scratch ////////////////////////////////
		
		/// <summary>
		/// Writes out the given byte buffer to the output stream with the correct opcode prefix.
		/// To write an integer call writeBytes(out,val.EncodeMPI(false).ReverseBytes());
		/// </summary>
		/// <param name="stream"></param>
		/// <param name="buffer"></param>
		public static void writeBytes(Stream stream,byte[] buffer)
		{
			if(buffer.Length<OP_PUSHDATA1)
			{
				stream.Write((byte)buffer.Length);
				stream.Write(buffer);
			}
			else if(buffer.Length<256)
			{
				stream.Write(OP_PUSHDATA1);
				stream.Write((byte)buffer.Length);
				stream.Write(buffer);
			}
			else if(buffer.Length<65536)
			{
				stream.Write(OP_PUSHDATA2);
				stream.Write((byte)(0xFF & (buffer.Length)));
				stream.Write((byte)(0xFF & (buffer.Length>>8)));
				stream.Write(buffer);
			}
			else
			{ throw new NotImplementedException("Unimplemented"); }
		}

		public static byte[] createOutputScript(Address to)
		{
			// TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
			using(ByteStreamUnsafe stream=new ByteStreamUnsafe(24))
			{
				stream.Write(OP_DUP);
				stream.Write(OP_HASH160);
				writeBytes(stream,to.Hash160);
				stream.Write(OP_EQUALVERIFY);
				stream.Write(OP_CHECKSIG);

				return stream.ToArrayIrreversible();
			}
		}

		/// <summary>
		/// Create a script that sends coins directly to the given public key (eg in a coinbase transaction).
		/// </summary>
		/// <param name="pubkey"></param>
		/// <returns></returns>
		public static byte[] createOutputScript(byte[] pubkey)
		{
			// TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
			using(ByteStreamUnsafe stream=new ByteStreamUnsafe(pubkey.Length+1))
			{
				writeBytes(stream,pubkey);
				stream.Write(OP_CHECKSIG);

				return stream.ToArrayIrreversible();
			}
		}

		/**
		 * Creates a script that sends coins directly to the given public key. Same as
		 * {@link Script#createOutputScript(byte[])} but more type safe.
		 */
		public static byte[] createOutputScript(ECKey pubkey)
		{
			return createOutputScript(pubkey.PublicKey);
		}

		public static byte[] createInputScript(byte[] signature, byte[] pubkey)
		{
			// TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
			using(ByteStreamUnsafe stream=new ByteStreamUnsafe(signature.Length+pubkey.Length+2))
			{
				writeBytes(stream,signature);
				writeBytes(stream,pubkey);

				return stream.ToArrayIrreversible();
			}
		}

		public static byte[] createInputScript(byte[] signature)
		{
			// TODO: Do this by creating a Script *first* then having the script reassemble itself into bytes.
			using(ByteStreamUnsafe stream=new ByteStreamUnsafe(signature.Length+2))
			{
				writeBytes(stream,signature);
				return stream.ToArrayIrreversible();
			}
		}
    
		////////////////////// Interface used during verification of transactions/blocks ////////////////////////////////
		//throws ScriptException
		private static int getSigOpCount(IEnumerable<ScriptChunk> chunks,bool accurate)
		{
			int sigOps=0;
			int lastOpCode=OP_INVALIDOPCODE;
			foreach(ScriptChunk chunk in chunks)
			{
				if(chunk.IsOpCode)
				{
					int opcode=0xFF & chunk.Data[0];
					switch (opcode)
					{
						case OP_CHECKSIG:
						case OP_CHECKSIGVERIFY:
							sigOps++;
							break;

						case OP_CHECKMULTISIG:
						case OP_CHECKMULTISIGVERIFY:
							if(accurate && lastOpCode>=OP_1 && lastOpCode<=OP_16)
							{ sigOps+=getOpNValue(lastOpCode); }
							else
							{ sigOps+=20; }
							break;
					}

					lastOpCode=opcode;
				}
			}
			return sigOps;
		}
		
		/// <summary>
		/// Convince method to get the int value of OP_N.
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="opcode"></param>
		/// <returns></returns>
		private static int getOpNValue(int opcode)
		{
			if(opcode==OP_0)
			{ return 0; }

			if(opcode<OP_1 || opcode>OP_16) // This should absolutely never happen
			{ throw new ScriptException("getOpNValue called on non OP_N opcode"); }

			return opcode+1-OP_1;
		}

		/// <summary>
		/// Gets the count of regular SigOps in the script program (counting multisig ops as 20).
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="program"></param>
		/// <returns></returns>
		public static int getSigOpCount(byte[] program)
		{
			Script script=new Script();
			try
			{ script.parse(program,0,program.Length); }
			catch(ScriptException)	// Ignore errors and count up to the parse-able length
			{ }

			return getSigOpCount(script.chunks,false);
		}
    
		/// <summary>
		/// Gets the count of P2SH Sig Ops in the Script scriptSig.
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="scriptSig"></param>
		/// <returns></returns>
		public static long getP2SHSigOpCount(byte[] scriptSig)
		{
			Script script=new Script();
			try
			{ script.parse(scriptSig,0,scriptSig.Length); }
			catch (ScriptException)	// Ignore errors and count up to the parse-able length
			{ }

			for(int i=script.chunks.Count-1;i>=0;i--)
			{
				ScriptChunk chunk=script.chunks[i];
				if(!chunk.IsOpCode)
				{
					Script subScript=new Script();
					subScript.parse(chunk.Data,0,chunk.Data.Length);
					return getSigOpCount(subScript.chunks, true);
				}
			}
				
			return 0;
		}

		/**
		 * <p></p>
		 */
		/// <summary>
		/// Whether or not this is a scriptPubKey representing a pay-to-script-hash output.
		/// In such outputs, the logic that controls reclamation is not actually in the output at all.
		/// Instead there's just a hash, and it's up to the spending input to provide a program matching that hash.
		/// This rule is "soft enforced" by the network as it does not exist in Satoshis original implementation.
		/// It means blocks containing P2SH transactions that don't match correctly are considered valid, but won't be mined upon, so they'll be rapidly re-orgd out of the chain.
		/// This logic is defined by <a href="https://en.bitcoin.it/wiki/BIP_0016">BIP 16</a>.
		/// Bitcoin.NET does not support creation of P2SH transactions today.
		/// The goal of P2SH is to allow short addresses even for complex scripts (eg, multi-sig outputs) so they are convenient to work with in things like QRcodes or with copy/paste, and also to minimize the size of the unspent output set (which improves performance of the Bitcoin system).
		/// </summary>
		/// <returns></returns>
		public bool isPayToScriptHash()
		{
			return program.Length==23 &&
				   (program[0] & 0xff)==OP_HASH160 &&
				   (program[1] & 0xff)==0x14 &&
				   (program[22] & 0xff)==OP_EQUAL;
		}
		
		private static bool equalsRange(byte[] a,int start,byte[] b)
		{
			//TODO: Convert to a byte[] extension method
			if(b.Length>a.Length-start)
			{ return false; }
			
			for(int i=0;i<b.Length;i++)
			{
				if(a[i+start]!=b[i])
				{ return false; }
			}
				
			return true;
		}
    
		/// <summary>
		/// Returns the script bytes of inputScript with all instances of the specified script object removed
		/// </summary>
		/// <param name="inputScript"></param>
		/// <param name="chunkToRemove"></param>
		/// <returns></returns>
		public static byte[] removeAllInstancesOf(byte[] inputScript,byte[] chunkToRemove)
		{
			// We usually don't end up removing anything
			using(ByteStreamUnsafe stream=new ByteStreamUnsafe(inputScript.Length))
			{
				int cursor=0;
				while(cursor<inputScript.Length)
				{
					bool skip=equalsRange(inputScript,cursor,chunkToRemove);
            
					int opcode=inputScript[cursor++] & 0xFF;
					int additionalBytes=0;
					if(opcode>=0 && opcode<OP_PUSHDATA1)
					{ additionalBytes=opcode; }
					else if(opcode==OP_PUSHDATA1)
					{ additionalBytes=inputScript[cursor]+1; }
					else if(opcode==OP_PUSHDATA2)
					{
						additionalBytes=((0xFF & inputScript[cursor]) |
										((0xFF & inputScript[cursor+1])<<8))
										+2;
					}
					else if(opcode==OP_PUSHDATA4)
					{
						additionalBytes=((0xFF & inputScript[cursor]) |
										((0xFF & inputScript[cursor+1])<<8) |
										((0xFF & inputScript[cursor+1])<<16) |
										((0xFF & inputScript[cursor+1])<<24))
										+4;
					}

					if(!skip)
					{
						stream.Write((byte)opcode);
						stream.Write(inputScript,cursor,additionalBytes);
					}
					cursor+=additionalBytes;
				}

				return stream.ToArrayIrreversible();
			}
		}
    
		/// <summary>
		/// Returns the script bytes of inputScript with all instances of the given op code removed
		/// </summary>
		/// <param name="inputScript"></param>
		/// <param name="opCode"></param>
		/// <returns></returns>
		public static byte[] removeAllInstancesOfOp(byte[] inputScript,int opCode)
		{ return removeAllInstancesOf(inputScript,new[] { (byte)opCode} ); }
    
		////////////////////// Script verification and helpers ////////////////////////////////
    
		private static bool castToBool(byte[] data)
		{
			for(int i=0;i<data.Length;i++)
			{
				if(data[i]!=0)
				{
					// "Can be negative zero" -reference client (see OpenSSL's BN_bn2mpi)
					if(i==data.Length-1 && (data[i] & 0xFF)==0x80)
					{ return false; }
					return true;
				}
			}
			return false;
		}
    
		/// <summary>
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="chunk"></param>
		/// <returns></returns>
		private static BigInteger castToBigInteger(byte[] chunk)
		{
			if(chunk.Length>4)
			{ throw new ScriptException("Script attempted to use an integer larger than 4 bytes"); }
			return chunk.ReverseBytes().DecodeMPI(false);
		}
		
		/// <summary>
		/// <exception cref="ScriptException"></exception>
		/// </summary>
		/// <param name="txContainingThis"></param>
		/// <param name="index"></param>
		/// <param name="script"></param>
		/// <param name="stack"></param>
		private static void executeScript(Transaction txContainingThis,long index,Script script,Stack<byte[]> stack)
		{
			int opCount=0;
			int lastCodeSepLocation=0;
        
			Stack<byte[]> altstack=new Stack<byte[]>();
			Stack<bool> ifStack=new Stack<bool>();
        
			foreach(ScriptChunk chunk in script.chunks)
			{
				bool shouldExecute=!ifStack.Contains(false);
            
				if(!chunk.IsOpCode)
				{
					if(chunk.Data.Length>520)
					{ throw new ScriptException("Attempted to push a data string larger than 520 bytes"); }
                
					if(!shouldExecute)
					{ continue; }
                
					stack.Push(chunk.Data);
				}
				else
				{
					int opcode=0xFF & chunk.Data[0];
					if(opcode>OP_16)
					{
						opCount++;
						if(opCount>201)
						{ throw new ScriptException("More script operations than is allowed"); }
					}
                
					if(opcode==OP_VERIF || opcode==OP_VERNOTIF)
					{ throw new ScriptException("Script included OP_VERIF or OP_VERNOTIF"); }
                
					if(opcode==OP_CAT || opcode==OP_SUBSTR || opcode==OP_LEFT || opcode==OP_RIGHT || opcode==OP_INVERT || opcode==OP_AND || opcode==OP_OR || opcode==OP_XOR || opcode==OP_2MUL || opcode==OP_2DIV || opcode==OP_MUL || opcode==OP_DIV || opcode==OP_MOD || opcode==OP_LSHIFT || opcode==OP_RSHIFT)
					{ throw new ScriptException("Script included a disabled Script Op."); }
                
					switch (opcode)
					{
						case OP_IF:
							if(!shouldExecute)
							{
								ifStack.Push(false);
								continue;
							}
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_IF on an empty stack"); }
							ifStack.Push(castToBool(stack.Pop()));
							continue;

						case OP_NOTIF:
							if(!shouldExecute)
							{
								ifStack.Push(false);
								continue;
							}
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_NOTIF on an empty stack"); }
							ifStack.Push(!castToBool(stack.Pop()));
							continue;

						case OP_ELSE:
							if(ifStack.Count==0)
							{ throw new ScriptException("Attempted OP_ELSE without OP_IF/NOTIF"); }
							ifStack.Push(!ifStack.Pop());
							continue;

						case OP_ENDIF:
							if(ifStack.Count==0)
							{ throw new ScriptException("Attempted OP_ENDIF without OP_IF/NOTIF"); }
							ifStack.Pop();
							continue;
					}
                
					if(!shouldExecute)
					{ continue; }
                
					switch(opcode)
					{
						//case OP_0: dont know why this isnt also here in the reference client
						case OP_1NEGATE:
							stack.Push(MPIHelper.Encode(BigInteger.One.Negate(),false).ReverseBytes());
							break;

						case OP_1:
						case OP_2:
						case OP_3:
						case OP_4:
						case OP_5:
						case OP_6:
						case OP_7:
						case OP_8:
						case OP_9:
						case OP_10:
						case OP_11:
						case OP_12:
						case OP_13:
						case OP_14:
						case OP_15:
						case OP_16:
							stack.Push(MPIHelper.Encode(BigInteger.ValueOf(getOpNValue(opcode)),false).ReverseBytes());
							break;

						case OP_NOP:
							break;

						case OP_VERIFY:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_VERIFY on an empty stack"); }
							if(!castToBool(stack.Pop()))
							{ throw new ScriptException("OP_VERIFY failed"); }
							break;

						case OP_RETURN:
							throw new ScriptException("Script called OP_RETURN");

						case OP_TOALTSTACK:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_TOALTSTACK on an empty stack"); }
							altstack.Push(stack.Pop());
							break;

						case OP_FROMALTSTACK:
							if(altstack.Count<1)
							{ throw new ScriptException("Attempted OP_TOALTSTACK on an empty altstack"); }
							stack.Push(altstack.Pop());
							break;

						case OP_2DROP:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted OP_2DROP on a stack with size<2"); }
							stack.Pop();
							stack.Pop();
							break;

						case OP_2DUP:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted OP_2DUP on a stack with size<2"); }
							
							Iterator<byte[]> it2DUP=stack.descendingIterator();
							byte[] OP2DUPtmpChunk2=it2DUP.next();
							stack.Push(it2DUP.next());
							stack.Push(OP2DUPtmpChunk2);
							break;

						case OP_3DUP:
							if(stack.Count<3)
							{ throw new ScriptException("Attempted OP_3DUP on a stack with size<3"); }
							
							Iterator<byte[]> it3DUP=stack.descendingIterator();
							byte[] OP3DUPtmpChunk3=it3DUP.next();
							byte[] OP3DUPtmpChunk2=it3DUP.next();
							stack.Push(it3DUP.next());
							stack.Push(OP3DUPtmpChunk2);
							stack.Push(OP3DUPtmpChunk3);
							break;

						case OP_2OVER:
							if(stack.Count<4)
							{ throw new ScriptException("Attempted OP_2OVER on a stack with size<4"); }

							Iterator<byte[]> it2OVER=stack.descendingIterator();
							it2OVER.next();
							it2OVER.next();
							byte[] OP2OVERtmpChunk2=it2OVER.next();
							stack.Push(it2OVER.next());
							stack.Push(OP2OVERtmpChunk2);
							break;

						case OP_2ROT:
							if(stack.Count<6)
							{ throw new ScriptException("Attempted OP_2ROT on a stack with size<6"); }

							byte[] OP2ROTtmpChunk6=stack.Pop();
							byte[] OP2ROTtmpChunk5=stack.Pop();
							byte[] OP2ROTtmpChunk4=stack.Pop();
							byte[] OP2ROTtmpChunk3=stack.Pop();
							byte[] OP2ROTtmpChunk2=stack.Pop();
							byte[] OP2ROTtmpChunk1=stack.Pop();
							stack.Push(OP2ROTtmpChunk3);
							stack.Push(OP2ROTtmpChunk4);
							stack.Push(OP2ROTtmpChunk5);
							stack.Push(OP2ROTtmpChunk6);
							stack.Push(OP2ROTtmpChunk1);
							stack.Push(OP2ROTtmpChunk2);
							break;

						case OP_2SWAP:
							if(stack.Count<4)
							{ throw new ScriptException("Attempted OP_2SWAP on a stack with size<4"); }

							byte[] OP2SWAPtmpChunk4=stack.Pop();
							byte[] OP2SWAPtmpChunk3=stack.Pop();
							byte[] OP2SWAPtmpChunk2=stack.Pop();
							byte[] OP2SWAPtmpChunk1=stack.Pop();
							stack.Push(OP2SWAPtmpChunk3);
							stack.Push(OP2SWAPtmpChunk4);
							stack.Push(OP2SWAPtmpChunk1);
							stack.Push(OP2SWAPtmpChunk2);
							break;

						case OP_IFDUP:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_IFDUP on an empty stack"); }
							if(castToBool(stack.getLast()))
							{ stack.Push(stack.getLast()); }
							break;

						case OP_DEPTH:
							stack.Push(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.Count), false)));
							break;

						case OP_DROP:
							if(stack.Count<1)
								throw new ScriptException("Attempted OP_DROP on an empty stack");
							stack.Pop();
							break;

						case OP_DUP:
							if(stack.Count<1)
								throw new ScriptException("Attempted OP_DUP on an empty stack");
							stack.Push(stack.getLast());
							break;

						case OP_NIP:
							if(stack.Count<2)
								throw new ScriptException("Attempted OP_NIP on a stack with size < 2");
							byte[] OPNIPtmpChunk=stack.Pop();
							stack.Pop();
							stack.Push(OPNIPtmpChunk);
							break;

						case OP_OVER:
							if(stack.Count<2)
								throw new ScriptException("Attempted OP_OVER on a stack with size < 2");
							Iterator<byte[]> itOVER=stack.descendingIterator();
							itOVER.next();
							stack.Push(itOVER.next());
							break;

						case OP_PICK:
						case OP_ROLL:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_PICK/OP_ROLL on an empty stack"); }
							
							long val=castToBigInteger(stack.Pop()).longValue();
							if(val<0 || val >= stack.Count)
							{ throw new ScriptException("OP_PICK/OP_ROLL attempted to get data deeper than stack size"); }
							Iterator<byte[]> itPICK=stack.descendingIterator();
							for(long i=0; i<val; i++)
							{ itPICK.next(); }
							byte[] OPROLLtmpChunk=itPICK.next();
							if(opcode == OP_ROLL)
							{ itPICK.remove(); }
							stack.Push(OPROLLtmpChunk);
							break;

						case OP_ROT:
							if(stack.Count<3)
							{ throw new ScriptException("Attempted OP_ROT on a stack with size<3"); }

							byte[] OPROTtmpChunk3=stack.Pop();
							byte[] OPROTtmpChunk2=stack.Pop();
							byte[] OPROTtmpChunk1=stack.Pop();
							stack.Push(OPROTtmpChunk2);
							stack.Push(OPROTtmpChunk3);
							stack.Push(OPROTtmpChunk1);
							break;

						case OP_SWAP:
						case OP_TUCK:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted OP_SWAP on a stack with size<2"); }

							byte[] OPSWAPtmpChunk2=stack.Pop();
							byte[] OPSWAPtmpChunk1=stack.Pop();
							stack.Push(OPSWAPtmpChunk2);
							stack.Push(OPSWAPtmpChunk1);
							if(opcode == OP_TUCK)
							{ stack.Push(OPSWAPtmpChunk2); }
							break;

						case OP_CAT:
						case OP_SUBSTR:
						case OP_LEFT:
						case OP_RIGHT:
							throw new ScriptException("Attempted to use disabled Script Op");

						case OP_SIZE:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_SIZE on an empty stack"); }
							stack.Push(Utils.reverseBytes(Utils.encodeMPI(BigInteger.valueOf(stack.getLast().Length), false)));
							break;

						case OP_INVERT:
						case OP_AND:
						case OP_OR:
						case OP_XOR:
							throw new ScriptException("Attempted to use disabled Script Op.");
						case OP_EQUAL:
							if(stack.Count<2)
								throw new ScriptException("Attempted OP_EQUALVERIFY on a stack with size<2");
							stack.Push(Arrays.Equals(stack.Pop(), stack.Pop()) ? new byte[] {1} : new byte[] {0});
							break;
						case OP_EQUALVERIFY:
							if(stack.Count<2)
								throw new ScriptException("Attempted OP_EQUALVERIFY on a stack with size<2");
							if(!Arrays.Equals(stack.Pop(), stack.Pop()))
								throw new ScriptException("OP_EQUALVERIFY: non-equal data");
							break;
						case OP_1ADD:
						case OP_1SUB:
						case OP_NEGATE:
						case OP_ABS:
						case OP_NOT:
						case OP_0NOTEQUAL:
							if(stack.Count<1)
								throw new ScriptException("Attempted a numeric op on an empty stack");
							BigInteger numericOPnum=castToBigInteger(stack.Pop());
                                        
							switch (opcode) {
							case OP_1ADD:
								numericOPnum=numericOPnum.Add(BigInteger.One);
								break;
							case OP_1SUB:
								numericOPnum=numericOPnum.Subtract(BigInteger.One);
								break;
							case OP_NEGATE:
								numericOPnum=numericOPnum.negate();
								break;
							case OP_ABS:
								if(numericOPnum.CompareTo(BigInteger.Zero)<0)
									numericOPnum=numericOPnum.negate();
								break;
							case OP_NOT:
								if(numericOPnum.Equals(BigInteger.Zero))
									numericOPnum=BigInteger.One;
								else
									numericOPnum=BigInteger.Zero;
								break;
							case OP_0NOTEQUAL:
								if(numericOPnum.Equals(BigInteger.Zero))
									numericOPnum=BigInteger.Zero;
								else
									numericOPnum=BigInteger.One;
								break;
							}
                    
							stack.Push(Utils.reverseBytes(Utils.encodeMPI(numericOPnum, false)));
							break;
						case OP_2MUL:
						case OP_2DIV:
							throw new ScriptException("Attempted to use disabled Script Op.");
						case OP_ADD:
						case OP_SUB:
						case OP_BOOLAND:
						case OP_BOOLOR:
						case OP_NUMEQUAL:
						case OP_NUMNOTEQUAL:
						case OP_LESSTHAN:
						case OP_GREATERTHAN:
						case OP_LESSTHANOREQUAL:
						case OP_GREATERTHANOREQUAL:
						case OP_MIN:
						case OP_MAX:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted a numeric op on a stack with size<2"); }
							BigInteger numericOPnum2=castToBigInteger(stack.Pop());
							BigInteger numericOPnum1=castToBigInteger(stack.Pop());

							BigInteger numericOPresult;
							switch (opcode)
							{
								case OP_ADD:
									numericOPresult=numericOPnum1.Add(numericOPnum2);
									break;

								case OP_SUB:
									numericOPresult=numericOPnum1.Subtract(numericOPnum2);
									break;

								case OP_BOOLAND:
									if(!numericOPnum1.Equals(BigInteger.Zero) && !numericOPnum2.Equals(BigInteger.Zero))
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_BOOLOR:
									if(!numericOPnum1.Equals(BigInteger.Zero) || !numericOPnum2.Equals(BigInteger.Zero))
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_NUMEQUAL:
									if(numericOPnum1.Equals(numericOPnum2))
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_NUMNOTEQUAL:
									if(!numericOPnum1.Equals(numericOPnum2))
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_LESSTHAN:
									if(numericOPnum1.CompareTo(numericOPnum2)<0)
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_GREATERTHAN:
									if(numericOPnum1.CompareTo(numericOPnum2)>0)
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_LESSTHANOREQUAL:
									if(numericOPnum1.CompareTo(numericOPnum2)<=0)
										numericOPresult=BigInteger.One;
									else
										numericOPresult=BigInteger.Zero;
									break;

								case OP_GREATERTHANOREQUAL:
									if(numericOPnum1.CompareTo(numericOPnum2)>=0)
									{ numericOPresult=BigInteger.One; }
									else
									{ numericOPresult=BigInteger.Zero; }
									break;

								case OP_MIN:
									if(numericOPnum1.CompareTo(numericOPnum2)<0)
									{ numericOPresult=numericOPnum1; }
									else
									{ numericOPresult=numericOPnum2; }
									break;

								case OP_MAX:
									if(numericOPnum1.CompareTo(numericOPnum2) > 0)
									{ numericOPresult=numericOPnum1; }
									else
									{ numericOPresult=numericOPnum2; }
									break;

								default:
									throw new RuntimeException("Opcode switched at runtime?");
							}
                    
							stack.Push(Utils.reverseBytes(Utils.encodeMPI(numericOPresult, false)));
							break;
						case OP_MUL:
						case OP_DIV:
						case OP_MOD:
						case OP_LSHIFT:
						case OP_RSHIFT:
							throw new ScriptException("Attempted to use disabled Script Op.");
						case OP_NUMEQUALVERIFY:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted OP_NUMEQUALVERIFY on a stack with size<2"); }
							BigInteger OPNUMEQUALVERIFYnum2=castToBigInteger(stack.Pop());
							BigInteger OPNUMEQUALVERIFYnum1=castToBigInteger(stack.Pop());
                    
							if(!OPNUMEQUALVERIFYnum1.Equals(OPNUMEQUALVERIFYnum2))
							{ throw new ScriptException("OP_NUMEQUALVERIFY failed"); }
							break;
						case OP_WITHIN:
							if(stack.Count<3)
							{ throw new ScriptException("Attempted OP_WITHIN on a stack with size<3"); }
							BigInteger OPWITHINnum3=castToBigInteger(stack.Pop());
							BigInteger OPWITHINnum2=castToBigInteger(stack.Pop());
							BigInteger OPWITHINnum1=castToBigInteger(stack.Pop());
							if(OPWITHINnum2.CompareTo(OPWITHINnum1) <= 0 && OPWITHINnum1.CompareTo(OPWITHINnum3)<0)
							{ stack.Push(Utils.reverseBytes(Utils.encodeMPI(BigInteger.One, false))); }
							else
							{ stack.Push(Utils.reverseBytes(Utils.encodeMPI(BigInteger.Zero, false))); }
							break;

						case OP_RIPEMD160:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_RIPEMD160 on an empty stack"); }

							RIPEMD160Digest digest=new RIPEMD160Digest();
							byte[] dataToHash=stack.Pop();
							digest.update(dataToHash, 0, dataToHash.Length);
							byte[] ripmemdHash=new byte[20];
							digest.doFinal(ripmemdHash, 0);
							stack.Push(ripmemdHash);
							break;

						case OP_SHA1:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_SHA1 on an empty stack"); }
							stack.Push(MessageDigest.getInstance("SHA-1").digest(stack.Pop()));
							break;

						case OP_SHA256:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_SHA256 on an empty stack"); }
							stack.Push(MessageDigest.getInstance("SHA-256").digest(stack.Pop()));
							break;

						case OP_HASH160:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_HASH160 on an empty stack"); }
							stack.Push(Utils.sha256hash160(stack.Pop()));
							break;

						case OP_HASH256:
							if(stack.Count<1)
							{ throw new ScriptException("Attempted OP_SHA256 on an empty stack"); }
							stack.Push(Utils.doubleDigest(stack.Pop()));
							break;

						case OP_CODESEPARATOR:
							lastCodeSepLocation=chunk.startLocationInProgram + 1;
							break;

						case OP_CHECKSIG:
						case OP_CHECKSIGVERIFY:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted OP_CHECKSIG(VERIFY) on a stack with size<2"); }
							byte[] CHECKSIGpubKey=stack.Pop();
							byte[] CHECKSIGsig=stack.Pop();
                    
							byte[] CHECKSIGconnectedScript=Arrays.copyOfRange(script.program, lastCodeSepLocation, script.program.Length);
                    
							UnsafeByteArrayOutputStream OPCHECKSIGOutStream=new UnsafeByteArrayOutputStream(CHECKSIGsig.Length + 1);
							writeBytes(OPCHECKSIGOutStream,CHECKSIGsig);
							CHECKSIGconnectedScript=removeAllInstancesOf(CHECKSIGconnectedScript, OPCHECKSIGOutStream.toByteArray());
                    
							// TODO: Use int for indexes everywhere, we can't have that many inputs/outputs
							Sha256Hash CHECKSIGhash=txContainingThis.hashTransactionForSignature((int)index,CHECKSIGconnectedScript,CHECKSIGsig[CHECKSIGsig.Length-1]);
                                        
							bool CHECKSIGsigValid;
							try
							{
								CHECKSIGsigValid=ECKey.verify(CHECKSIGhash.getBytes(), Arrays.copyOf(CHECKSIGsig, CHECKSIGsig.Length - 1), CHECKSIGpubKey);
							}
							catch(Exception)
							{
								// There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
								// Because I can't verify there aren't more, we use a very generic Exception catch
								CHECKSIGsigValid=false;
							}
                    
							if(opcode==OP_CHECKSIG)
							{ stack.Push(CHECKSIGsigValid?new byte[] {1}:new byte[] {0}); }
							else if(opcode==OP_CHECKSIGVERIFY)
							{
								if(!CHECKSIGsigValid)
								{ throw new ScriptException("Script failed OP_CHECKSIGVERIFY"); }
							}
							break;
						case OP_CHECKMULTISIG:
						case OP_CHECKMULTISIGVERIFY:
							if(stack.Count<2)
							{ throw new ScriptException("Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size<2"); }
							int CHECKMULTISIGpubKeyCount=castToBigInteger(stack.Pop()).intValue();
							if(CHECKMULTISIGpubKeyCount<0 || CHECKMULTISIGpubKeyCount > 20)
							{ throw new ScriptException("OP_CHECKMULTISIG(VERIFY) with pubkey count out of range"); }
							opCount+=CHECKMULTISIGpubKeyCount;
							
							if(opCount>201)
							{ throw new ScriptException("Total op count > 201 during OP_CHECKMULTISIG(VERIFY)"); }

							if(stack.Count<CHECKMULTISIGpubKeyCount+1)
							{ throw new ScriptException("Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size<num_of_pubkeys + 2"); }
                    
							LinkedList<byte[]> CHECKMULTISIGpubkeys=new LinkedList<byte[]>();
							for(int i=0; i<CHECKMULTISIGpubKeyCount; i++)
								CHECKMULTISIGpubkeys.Add(stack.Pop());
                    
							int CHECKMULTISIGsigCount=castToBigInteger(stack.Pop()).intValue();
							if(CHECKMULTISIGsigCount<0 || CHECKMULTISIGsigCount > CHECKMULTISIGpubKeyCount)
								throw new ScriptException("OP_CHECKMULTISIG(VERIFY) with sig count out of range");
							if(stack.Count<CHECKMULTISIGsigCount + 1)
								throw new ScriptException("Attempted OP_CHECKMULTISIG(VERIFY) on a stack with size<num_of_pubkeys + num_of_signatures + 3");
                    
							LinkedList<byte[]> CHECKMULTISIGsigs=new LinkedList<byte[]>();
							for(int i=0; i<CHECKMULTISIGsigCount; i++)
								CHECKMULTISIGsigs.Add(stack.Pop());
                    
							byte[] CHECKMULTISIGconnectedScript=Arrays.copyOfRange(script.program, lastCodeSepLocation, script.program.Length);
                    
							foreach(byte[] CHECKMULTISIGsig in CHECKMULTISIGsigs)
							{
								UnsafeByteArrayOutputStream OPCHECKMULTISIGOutStream=new UnsafeByteArrayOutputStream(CHECKMULTISIGsig.Length + 1);
								writeBytes(OPCHECKMULTISIGOutStream,CHECKMULTISIGsig);
								CHECKMULTISIGconnectedScript=removeAllInstancesOf(CHECKMULTISIGconnectedScript, OPCHECKMULTISIGOutStream.toByteArray());
							}
                    
							bool CHECKMULTISIGValid=true;
							while (CHECKMULTISIGsigs.Count > 0) {
								byte[] CHECKMULTISIGsig=CHECKMULTISIGsigs.getFirst();
								byte[] CHECKMULTISIGpubKey=CHECKMULTISIGpubkeys.pollFirst();
                        
								// We could reasonably move this out of the loop,
								// but because signature verification is significantly more expensive than hashing, its not a big deal
								Sha256Hash CHECKMULTISIGhash=txContainingThis.hashTransactionForSignature((int)index, CHECKMULTISIGconnectedScript,
										CHECKMULTISIGsig[CHECKMULTISIGsig.Length - 1]);
								try {
									if(ECKey.verify(CHECKMULTISIGhash.getBytes(), Arrays.copyOf(CHECKMULTISIGsig, CHECKMULTISIGsig.Length - 1), CHECKMULTISIGpubKey))
										CHECKMULTISIGsigs.pollFirst();
								} catch (Exception e) {
									// There is (at least) one exception that could be hit here (EOFException, if the sig is too short)
									// Because I can't verify there aren't more, we use a very generic Exception catch
								}
                        
								if(CHECKMULTISIGsigs.Count > CHECKMULTISIGpubkeys.Count)
								{
									CHECKMULTISIGValid=false;
									break;
								}
							}
                    
							// We uselessly remove a stack object to emulate a reference client bug
							stack.Pop();
                    
							if(opcode == OP_CHECKMULTISIG)
							{ stack.Push(CHECKMULTISIGValid?new byte[] {1}:new byte[] {0}); }
							else if(opcode==OP_CHECKMULTISIGVERIFY)
							{
								if(!CHECKMULTISIGValid)
								{ throw new ScriptException("Script failed OP_CHECKMULTISIGVERIFY"); }
							}
							break;

						case OP_NOP1:
						case OP_NOP2:
						case OP_NOP3:
						case OP_NOP4:
						case OP_NOP5:
						case OP_NOP6:
						case OP_NOP7:
						case OP_NOP8:
						case OP_NOP9:
						case OP_NOP10:
							break;
                    
						default:
							throw new ScriptException("Script used a reserved Op Code");
					}
				}
            
				if(stack.Count+altstack.Count>1000 || stack.Count+altstack.Count<0)
				{ throw new ScriptException("Stack size exceeded range"); }
			}
        
			if(ifStack.Count!=0)
			{ throw new ScriptException("OP_IF/OP_NOTIF without OP_ENDIF"); }
		}

		/**
		 * Verifies that this script (interpreted as a scriptSig) correctly spends the given scriptPubKey.
		 * @param txContainingThis The transaction in which this input scriptSig resides.
		 * @param scriptSigIndex The index in txContainingThis of the scriptSig (note: NOT the index of the scriptPubKey).
		 * @param scriptPubKey The connected scriptPubKey containing the conditions needed to claim the value.
		 * @param enforceP2SH Whether "pay to script hash" rules should be enforced. If in doubt, set to true.
		 * @throws VerificationException if this script does not correctly spend the scriptPubKey
		 * throws ScriptException
		 */
		public void correctlySpends(Transaction txContainingThis,long scriptSigIndex,Script scriptPubKey,bool enforceP2SH)
		{
			if(program.Length>10000 || scriptPubKey.program.Length>10000)
			{ throw new ScriptException("Script larger than 10,000 bytes"); }
        
			Stack<byte[]> stack=new Stack<byte[]>();
			Stack<byte[]> p2shStack=null;
        
			executeScript(txContainingThis,scriptSigIndex,this,stack);
			if(enforceP2SH)
			{ p2shStack=new Stack<byte[]>(stack); }
			executeScript(txContainingThis,scriptSigIndex,scriptPubKey,stack);
        
			if(stack.Count==0)
			{ throw new ScriptException("Stack empty at end of script execution."); }
        
			if(!castToBool(stack.Pop()))
			{ throw new ScriptException("Script resulted in a non-true stack"); }

			// P2SH is pay to script hash. It means that the scriptPubKey has a special form which is a valid
			// program but it has "useless" form that if evaluated as a normal program always returns true.
			// Instead, miners recognize it as special based on its template - it provides a hash of the real scriptPubKey
			// and that must be provided by the input. The goal of this bizarre arrangement is twofold:
			//
			// (1) You can sum up a large, complex script (like a CHECKMULTISIG script) with an address that's the same
			//     size as a regular address. This means it doesn't overload scannable QR codes/NFC tags or become
			//     un-wieldy to copy/paste.
			// (2) It allows the working set to be smaller: nodes perform best when they can store as many unspent outputs
			//     in RAM as possible, so if the outputs are made smaller and the inputs get bigger, then it's better for
			//     overall scalability and performance.

			// TODO: Check if we can take out enforceP2SH if there's a checkpoint at the enforcement block.
			if(enforceP2SH && scriptPubKey.isPayToScriptHash())
			{
				foreach(ScriptChunk chunk in chunks)
				{
					if(chunk.IsOpCode && (chunk.Data[0] & 0xff) > OP_16)
					{ throw new ScriptException("Attempted to spend a P2SH scriptPubKey with a script that contained script ops"); }
				}
					
            
				byte[] scriptPubKeyBytes=p2shStack.Pop();
				Script scriptPubKeyP2SH=new Script(parameters,scriptPubKeyBytes,0,scriptPubKeyBytes.Length);
            
				executeScript(txContainingThis,scriptSigIndex,scriptPubKeyP2SH,p2shStack);
            
				if(p2shStack.Count==0)
				{ throw new ScriptException("P2SH stack empty at end of script execution."); }
            
				if(!castToBool(p2shStack.Pop()))
				{ throw new ScriptException("P2SH script execution resulted in a non-true stack"); }
			}
		}
	}
}

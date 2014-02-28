using System;
using System.IO;

namespace BitcoinNET.Utils.Objects
{
	public class ByteStreamUnsafe:Stream
	{
		public byte[] Stream;
		
		public override long Position { get; set; }
		public override bool CanRead { get { return true; } }
		public override bool CanSeek { get { return true; } }
		public override bool CanWrite { get { return true; } }
		public override long Length { get { return Stream.Length; } }

		private ReaderWriterLockDisposable locker;

		//TODO: Overflow MUST increment the stream length in order to be usable
		public ByteStreamUnsafe(int streamLength)
		{
			locker=new ReaderWriterLockDisposable();

			using(locker.AcquireWriterLock())
			{
				Position=0;
				Stream=new byte[streamLength];
			}
		}

		public override void Flush()
		{ Stream=new byte[Stream.Length]; }

		public override long Seek(long offset,SeekOrigin origin)
		{
			switch(origin)
			{
				case SeekOrigin.Begin:
					Position=offset;
					break;

				case SeekOrigin.Current:
					Position+=offset;
					break;

				case SeekOrigin.End:
					Position=Length+offset-1;
					break;
			}

			return Position;
		}

		public override void SetLength(long value)
		{
			using(locker.AcquireWriterLock())
			{ Array.Resize(ref Stream,(int)value); }
		}

		public override int Read(byte[] buffer,int offset,int count)
		{
			//We are reading but writing the Position index, so we must use a WriterLock
			using(locker.AcquireWriterLock())
			{
				int i;
				for(i=0;i<count && Position<Length && i+offset<buffer.Length;i++)
				{ buffer[i+offset]=Stream[Position++]; }
				return i;
			}
		}
		
		public override void Write(byte[] buffer,int offset,int count)
		{
			using(locker.AcquireWriterLock())
			{
				for(int i=0;i<count && Position<Length && i+offset<buffer.Length;i++)
				{ Stream[Position++]=buffer[i+offset]; }
			}
		}


		public byte[] ToArray()
		{
			if(Position==Length)
			{ return Stream; }

			using(locker.AcquireReaderLock())
			{
				byte[] buffer=new byte[Position];
				Array.Copy(Stream,buffer,Position);
				return buffer;
			}
		}
		public byte[] ToArrayIrreversible()
		{
			if(Position==Length)
			{ return Stream; }

			SetLength(Position);
			return Stream;
		}


		protected override void Dispose(bool disposing)
		{
			using(locker.AcquireWriterLock())
			{
				base.Dispose(disposing);
				Stream=null;
				locker=null;
			}
		}
	}
}

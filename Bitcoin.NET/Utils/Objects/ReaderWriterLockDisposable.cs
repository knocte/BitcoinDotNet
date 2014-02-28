using System;
using System.Threading;

namespace BitcoinNET.Utils.Objects
{
	public class ReaderWriterLockDisposable
	{
		private const int defaultTimeout=2000;
		public readonly ReaderWriterLock Locker;
		public ReaderWriterLockDisposable()
		{ Locker=new ReaderWriterLock(); }

		public IDisposable AcquireReaderLock()
		{
			Locker.AcquireReaderLock(defaultTimeout);
			return getReleaseReaderLockDisposableObject();
		}
		public IDisposable AcquireReaderLock(int millisecondsTimeout)
		{
			Locker.AcquireReaderLock(millisecondsTimeout);
			return getReleaseReaderLockDisposableObject();
		}
		public IDisposable AcquireReaderLock(TimeSpan timeout)
		{
			Locker.AcquireReaderLock(timeout);
			return getReleaseReaderLockDisposableObject();
		}

		public IDisposable AcquireWriterLock()
		{
			Locker.AcquireWriterLock(defaultTimeout);
			return getReleaseWriterLockDisposableObject();
		}
		public IDisposable AcquireWriterLock(int millisecondsTimeout)
		{
			Locker.AcquireWriterLock(millisecondsTimeout);
			return getReleaseWriterLockDisposableObject();
		}
		public IDisposable AcquireWriterLock(TimeSpan timeout)
		{
			Locker.AcquireWriterLock(timeout);
			return getReleaseWriterLockDisposableObject();
		}

		private IDisposable getReleaseReaderLockDisposableObject()
		{ return new GenericDisposable(() => Locker.ReleaseReaderLock()); }
		private IDisposable getReleaseWriterLockDisposableObject()
		{ return new GenericDisposable(() => Locker.ReleaseWriterLock()); }
	}
}

using System;

namespace BitcoinNET.Utils.Objects
{
	public class GenericDisposable:IDisposable
	{
		private Action dispose;
		public GenericDisposable(Action dispose)
		{ this.dispose=dispose; }

		public void Dispose()
		{
			if(dispose!=null)
			{
				lock(this)
				{
					if(dispose!=null)
					{
						dispose();
						dispose=null;
					}
				}
			}
		}
		public ~GenericDisposable()
		{ Dispose(); }
	}
}

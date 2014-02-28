namespace BitcoinNET.BitcoinObjects.Script
{
	public class ScriptChunk
	{
		public bool IsOpCode;
		public byte[] Data;
		public int StartLocationInProgram;

		public ScriptChunk(bool isOpCode,byte[] data,int startLocationInProgram)
		{
			IsOpCode=isOpCode;
			Data=data;
			StartLocationInProgram=startLocationInProgram;
		}

		public bool EqualsOpCode(int opCode)
		{ return IsOpCode && Data.Length==1 && (0xFF & Data[0])==opCode; }
	}
}

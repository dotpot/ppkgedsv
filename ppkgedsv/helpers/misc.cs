using System;

namespace ppkgedsv
{
	public static class misc
	{
		private static void Print(string text){
			Console.WriteLine (String.Format("\n[{0}] {1}", DateTime.Now.ToString(), text));
		}
	}
}


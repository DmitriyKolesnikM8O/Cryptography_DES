using System;

namespace CryptoLib.Core
{
	public static class BitPermutation
	{
		/// <summary>
		/// Перестановка битов.
		/// </summary>
		/// <param name="inputValue">Массив байтов для перестановки.</param>
        /// <param name="pBlock">Правило перестановки (P-блок) - массив индексов битов входного значения, 
        /// где каждый элемент указывает, какой бит входного значения (по его индексу) 
        /// должен стать битом с текущим индексом в выходном значении.</param>
        /// <param name="indexFromLsb">Правила индексирования битов: true - от младшего к старшему,
		/// false - наоборот.</param>
        /// <param name="startIndexZero">Номер начального бита: true - 0, false - 1.</param>
        /// <returns>Массив байтов с переставленными битами.</returns>
		public static byte[] PermuteBits(
			byte[] inputValue,
			int[] pBlock,
			bool indexingRule,
			bool zeroIndex)
		{
			if (inputValue == null || pBlock == null) throw new Exception("Input value or pBlock cannot be null");

			int 
		}
								
	}
}

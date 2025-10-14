using System;
using System.Linq;

namespace CryptoLib.Core
{
	/// <summary>
    /// Реализует операции перестановки битов согласно заданному P-блоку.
    /// Поддерживает различные режимы индексирования битов и нумерации.
    /// </summary>
    public static class BitPermutation
	{
		/// <summary>
        /// Выполняет перестановку битов согласно заданному P-блоку.
        /// </summary>
		/// <param name="inputValue">Входной массив байтов для перестановки</param>
        /// <param name="pBlock">
        /// P-блок - массив индексов, определяющий порядок перестановки битов.
        /// Каждый элемент указывает позицию бита во входном массиве, который должен быть
        /// помещен в соответствующую позицию выходного массива.
		/// </param>
		/// <param name="indexingRule">
        /// Правило индексирования битов:
        /// - true: LSB (Least Significant Bit) - биты индексируются от младшего к старшему
        /// - false: MSB (Most Significant Bit) - биты индексируются от старшего к младшему
        /// 
        /// LSB режим (indexingRule = true):
        /// Байт: [b7 b6 b5 b4 b3 b2 b1 b0] - бит 0 = b0 (младший), бит 7 = b7 (старший)
        /// 
        /// MSB режим (indexingRule = false):
        /// Байт: [b0 b1 b2 b3 b4 b5 b6 b7] - бит 0 = b0 (старший), бит 7 = b7 (младший)
        /// </param>
		/// <param name="zeroIndex">
        /// Нумерация начального бита:
        /// - true: нумерация начинается с 0 (биты: 0, 1, 2, ...)
        /// - false: нумерация начинается с 1 (биты: 1, 2, 3, ...)
        /// </param>
        /// <returns>
        /// Массив байтов с переставленными битами согласно P-блоку.
        /// Размер выходного массива определяется длиной P-блока.
        /// </returns>
		public static byte[] PermutationBytes(
			byte[] inputValue,
			int[] pBlock,
			bool indexingRule,
			bool zeroIndex)
		{
			if (inputValue == null || pBlock == null)
				throw new ArgumentException("Входной массив или P-Block пустые в PermutationBytes");

			int inputBitLength = inputValue.Length * 8;
			int outputBitLength = pBlock.Length;
			int outputByteLength = (outputBitLength + 7) / 8;
			byte[] result = new byte[outputByteLength];

			int indexOffset = zeroIndex ? 0 : 1;

			int maxIndex = inputBitLength - (zeroIndex ? 1 : 0);
			if (pBlock.Any(index => index < indexOffset || index > maxIndex + indexOffset))
			{
				throw new ArgumentException($"P-Block имеет значение за пределами ({indexOffset} - {maxIndex + indexOffset}) в PermutationBytes");
			}

			for (int i = 0; i < pBlock.Length; i++)
			{
				int sourceBitIndex = pBlock[i] - indexOffset;
				bool bitValue = indexingRule ?
					GetBitLSB(inputValue, sourceBitIndex) :
					GetBitMSB(inputValue, sourceBitIndex);

				if (indexingRule)
				{

					SetBitLSB(result, i, bitValue);
				}
				else
				{

					SetBitMSB(result, i, bitValue);
				}
			}

			return result;
		}

		/// <summary>
        /// Извлекает значение бита из массива байтов в LSB режиме.
        /// </summary>
        /// <param name="data">Массив байтов</param>
        /// <param name="bitIndex">
        /// Индекс бита в LSB порядке:
        /// - Бит 0 = младший бит первого байта (data[0] & 0x01)
        /// - Бит 7 = старший бит первого байта (data[0] & 0x80)
        /// - Бит 8 = младший бит второго байта (data[1] & 0x01)
        /// </param>
		/// <returns>Значение бита (true = 1, false = 0)</returns>
		private static bool GetBitLSB(byte[] data, int bitIndex)
		{
			int byteIndex = bitIndex / 8;
			int bitInByte = bitIndex % 8;

			if (byteIndex < 0 || byteIndex >= data.Length)
				throw new ArgumentException($"Бит за границами в GetBitLSB: {bitIndex}");

			return (data[byteIndex] & (1 << bitInByte)) != 0;
		}

		/// <summary>
        /// Извлекает значение бита из массива байтов в MSB режиме.
        /// </summary>
        /// <param name="data">Массив байтов</param>
        /// <param name="bitIndex">
        /// Индекс бита в MSB порядке:
        /// - Бит 0 = старший бит первого байта (data[0] & 0x80)
        /// - Бит 7 = младший бит первого байта (data[0] & 0x01)
        /// - Бит 8 = старший бит второго байта (data[1] & 0x80)
        /// </param>
        /// <returns>Значение бита (true = 1, false = 0)</returns>
		private static bool GetBitMSB(byte[] data, int bitIndex)
		{
			int byteIndex = bitIndex / 8;
			int bitInByte = 7 - (bitIndex % 8);

			if (byteIndex < 0 || byteIndex >= data.Length)
				throw new ArgumentException($"Бит за границами в GetBitMSB: {bitIndex}");

			return (data[byteIndex] & (1 << bitInByte)) != 0;
		}
		/// <summary>
        /// Устанавливает значение бита в массиве байтов в LSB режиме.
        /// </summary>
        /// <param name="data">Массив байтов для модификации</param>
        /// <param name="bitIndex">
        /// Индекс бита для установки в LSB порядке:
        /// - Бит 0 = младший бит первого байта
        /// - Бит 7 = старший бит первого байта
        /// </param>
        /// <param name="value">Значение для установки (true = 1, false = 0)</param>
		private static void SetBitLSB(byte[] data, int bitIndex, bool value)
		{
			int byteIndex = bitIndex / 8;
			int bitInByte = bitIndex % 8;

			if (byteIndex >= data.Length)
				throw new ArgumentException($"Бит за границами в SetBitLSB: {bitIndex}");

			if (value)
				data[byteIndex] |= (byte)(1 << bitInByte);
			else
				data[byteIndex] &= (byte)~(1 << bitInByte);
		}

		/// <summary>
        /// Устанавливает значение бита в массиве байтов в MSB режиме.
        /// </summary>
        /// <param name="data">Массив байтов для модификации</param>
        /// <param name="bitIndex">
        /// Индекс бита для установки в MSB порядке:
        /// - Бит 0 = старший бит первого байта
        /// - Бит 7 = младший бит первого байта
        /// </param>
        /// <param name="value">Значение для установки (true = 1, false = 0)</param>
		private static void SetBitMSB(byte[] data, int bitIndex, bool value)
		{
			int byteIndex = bitIndex / 8;
			int bitInByte = 7 - (bitIndex % 8);

			if (byteIndex >= data.Length)
				throw new ArgumentException($"Бит за границами в SetBitMSB: {bitIndex}");

			if (value)
				data[byteIndex] |= (byte)(1 << bitInByte);
			else
				data[byteIndex] &= (byte)~(1 << bitInByte);
		}
	}
}
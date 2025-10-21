using System;

namespace CryptoLib.Core
{
    public static class BitPermutation
    {
        public static byte[] PermutationBytes(
            byte[] inputValue,
            int[] pBlock,
            bool indexingRule,
            bool zeroIndex)
        {
            if (inputValue == null || pBlock == null)
                throw new ArgumentException("Input array or P-Block is null in PermutationBytes");

            int outputBitLength = pBlock.Length;
            int outputByteLength = (outputBitLength + 7) / 8;
            byte[] result = new byte[outputByteLength];

            PermutationBytes(inputValue, pBlock, result, indexingRule, zeroIndex);
            return result;
        }

        public static void PermutationBytes(
            byte[] inputValue,
            int[] pBlock,
            byte[] destination,
            bool indexingRule,
            bool zeroIndex)
        {
            if (inputValue == null || pBlock == null || destination == null)
                throw new ArgumentException("Input, P-Block, or destination is null in PermutationBytes");

            if (destination.Length * 8 < pBlock.Length)
                throw new ArgumentException("Destination array is too small for the permutation result.");

            // === ВОССТАНОВЛЕННАЯ И УЛУЧШЕННАЯ ПРОВЕРКА ===
            int inputBitLength = inputValue.Length * 8;
            int indexOffset = zeroIndex ? 0 : 1;
            // Проверяем только минимальное и максимальное значения в P-блоке, это быстрее чем .Any()
            int minP = int.MaxValue, maxP = int.MinValue;
            for(int i = 0; i < pBlock.Length; i++)
            {
                if (pBlock[i] < minP) minP = pBlock[i];
                if (pBlock[i] > maxP) maxP = pBlock[i];
            }
            if (minP < indexOffset || maxP >= inputBitLength + indexOffset)
            {
                throw new ArgumentException($"P-Block contains an index out of the valid range.");
            }
            // ===============================================

            Array.Clear(destination, 0, destination.Length);

            for (int i = 0; i < pBlock.Length; i++)
            {
                int sourceBitIndex = pBlock[i] - indexOffset;
                bool bitValue = indexingRule ?
                    GetBitLSB(inputValue, sourceBitIndex) :
                    GetBitMSB(inputValue, sourceBitIndex);

                if (indexingRule)
                {
                    SetBitLSB(destination, i, bitValue);
                }
                else
                {
                    SetBitMSB(destination, i, bitValue);
                }
            }
        }

        private static bool GetBitLSB(byte[] data, int bitIndex)
        {
            return (data[bitIndex >> 3] & (1 << (bitIndex & 7))) != 0;
        }

        private static bool GetBitMSB(byte[] data, int bitIndex)
        {
            return (data[bitIndex >> 3] & (1 << (7 - (bitIndex & 7)))) != 0;
        }

        private static void SetBitLSB(byte[] data, int bitIndex, bool value)
        {
            int byteIndex = bitIndex >> 3;
            int bitInByte = bitIndex & 7;
            if (value)
                data[byteIndex] |= (byte)(1 << bitInByte);
            else
                data[byteIndex] &= (byte)~(1 << bitInByte);
        }

        private static void SetBitMSB(byte[] data, int bitIndex, bool value)
        {
            int byteIndex = bitIndex >> 3;
            int bitInByte = 7 - (bitIndex & 7);
            if (value)
                data[byteIndex] |= (byte)(1 << bitInByte);
            else
                data[byteIndex] &= (byte)~(1 << bitInByte);
        }
    }
}
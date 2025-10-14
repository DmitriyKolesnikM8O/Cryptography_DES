using System;
using CryptoLib.Core;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DES
{
    public class DESFeistelFunction : IFeistelFunction
    {
        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 4) // 32 бита
                throw new ArgumentException("Input block must be 32 bits (4 bytes)");
            if (roundKey.Length != 6) // 48 бит  
                throw new ArgumentException("Round key must be 48 bits (6 bytes)");

            // 1. Expansion permutation (32-bit -> 48-bit)
            byte[] expanded = BitPermutation.PermutationBytes(inputBlock, DESTables.E, false, false);

            // 2. XOR с раундовым ключом
            byte[] xored = XorWithKey(expanded, roundKey);

            // 3. S-Box substitution (48-bit -> 32-bit)
            byte[] substituted = SBoxSubstitution(xored);

            // 4. P permutation
            byte[] result = BitPermutation.PermutationBytes(substituted, DESTables.P, false, false);

            return result;
        }

        private byte[] XorWithKey(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i]);
            }
            return result;
        }

        private byte[] SBoxSubstitution(byte[] data)
        {
            byte[] result = new byte[4]; // 32 бита

            for (int i = 0; i < 8; i++)
            {
                // Берем 6 бит для каждого S-блока
                int byteIndex = i * 6 / 8;
                int bitOffset = (i * 6) % 8;
                
                int block;
                if (bitOffset <= 2)
                {
                    // Блок находится в одном байте
                    block = (data[byteIndex] >> (2 - bitOffset)) & 0x3F;
                }
                else
                {
                    // Блок разделен между двумя байтами
                    block = ((data[byteIndex] << (bitOffset - 2)) | (data[byteIndex + 1] >> (10 - bitOffset))) & 0x3F;
                }

                // Вычисляем строку и столбец
                int row = ((block & 0x20) >> 4) | (block & 0x01);
                int col = (block & 0x1E) >> 1;
                
                // Получаем значение из S-блока
                int sboxValue = DESTables.S_BOX[i, row, col];
                
                // Записываем 4 бита в результат
                int resultByteIndex = i / 2;
                int resultBitOffset = 4 * (1 - (i % 2));
                result[resultByteIndex] |= (byte)(sboxValue << resultBitOffset);
            }

            return result;
        }
    }
}
using System;
using CryptoLib.Core;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DES
{
    public class DESFeistelFunction : IFeistelFunction
    {
        // === БУФЕРЫ, ВЫНЕСЕННЫЕ В ПОЛЯ КЛАССА ===
        private readonly byte[] _expanded;      // 48-bit (6 bytes)
        private readonly byte[] _xored;         // 48-bit (6 bytes)
        private readonly byte[] _substituted;   // 32-bit (4 bytes)
        private readonly byte[] _result;        // 32-bit (4 bytes)

        public DESFeistelFunction()
        {
            // === ИНИЦИАЛИЗАЦИЯ БУФЕРОВ ОДИН РАЗ В КОНСТРУКТОРЕ ===
            _expanded = new byte[6];
            _xored = new byte[6];
            _substituted = new byte[4];
            _result = new byte[4];
        }

        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 4)
                throw new ArgumentException("Input block must be 32 bits (4 bytes)");
            if (roundKey.Length != 6)
                throw new ArgumentException("Round key must be 48 bits (6 bytes)");

            // 1. Expansion (32-bit -> 48-bit)
            // ПРЕДПОЛАГАЕТСЯ, что вы измените PermutationBytes, чтобы он писал в существующий массив
            BitPermutation.PermutationBytes(inputBlock, DESTables.E, _expanded, false, false);

            // 2. XOR с раундовым ключом
            XorWithKey(_expanded, roundKey, _xored);

            // 3. S-Box substitution (48-bit -> 32-bit)
            SBoxSubstitution(_xored, _substituted);

            // 4. P permutation
            BitPermutation.PermutationBytes(_substituted, DESTables.P, _result, false, false);

            return (byte[])_result.Clone();
        }

        // ПЕРЕПИСАННЫЙ МЕТОД: не возвращает новый массив, а пишет в `result`
        private void XorWithKey(byte[] data, byte[] key, byte[] result)
        {
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key[i]);
            }
        }

        // ПЕРЕПИСАННЫЙ МЕТОД: не возвращает новый массив, а пишет в `result`
        private void SBoxSubstitution(byte[] data, byte[] result)
        {
            // Обнуляем результат перед заполнением
            Array.Clear(result, 0, result.Length);

            for (int i = 0; i < 8; i++)
            {
                int byteIndex = i * 6 / 8;
                int bitOffset = (i * 6) % 8;
                
                int block;
                if (bitOffset <= 2)
                {
                    block = (data[byteIndex] >> (2 - bitOffset)) & 0x3F;
                }
                else
                {
                    block = ((data[byteIndex] << (bitOffset - 2)) | (data[byteIndex + 1] >> (10 - bitOffset))) & 0x3F;
                }

                int row = ((block & 0x20) >> 4) | (block & 0x01);
                int col = (block & 0x1E) >> 1;
                
                int sboxValue = DESTables.S_BOX[i, row, col];
                
                int resultByteIndex = i / 2;
                int resultBitOffset = 4 * (1 - (i % 2));
                result[resultByteIndex] |= (byte)(sboxValue << resultBitOffset);
            }
        }
    }
}
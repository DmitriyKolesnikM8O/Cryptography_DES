using System;
using CryptoLib.Core;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DES
{
    public class DESFeistelFunction : IFeistelFunction
    {
        // НЕТ ПОЛЕЙ-БУФЕРОВ. Класс полностью потокобезопасен.

        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 4)
                throw new ArgumentException("Input block must be 32 bits (4 bytes)");
            if (roundKey.Length != 6)
                throw new ArgumentException("Round key must be 48 bits (6 bytes)");

            // Все временные массивы создаются как локальные переменные.
            byte[] expanded = new byte[6];
            BitPermutation.PermutationBytes(inputBlock, DESTables.E, expanded, false, false);
            
            byte[] xored = XorWithKey(expanded, roundKey);
            
            byte[] substituted = SBoxSubstitution(xored);

            byte[] result = new byte[4];
            BitPermutation.PermutationBytes(substituted, DESTables.P, result, false, false);

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
            byte[] result = new byte[4];
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
            return result;
        }
    }
}
using System;
using CryptoLib.Core;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DES
{
    public class DESKeyScheduler : IKeyScheduler
    {
        public byte[][] ExpandKey(byte[] inputKey)
        {
            if (inputKey.Length != 8)
                throw new ArgumentException("DES key must be 64 bits (8 bytes)");

            byte[][] roundKeys = new byte[16][];

            // Применяем перестановку PC1 к ключу (64 бита -> 56 бит)
           byte[] pc1Key = BitPermutation.PermutationBytes(inputKey, DESTables.PC1, false, false);

            // Разделяем на две половины по 28 бит
            uint left = Get28Bits(pc1Key, 0);
            uint right = Get28Bits(pc1Key, 28);

            // Генерируем 16 раундовых ключей
            for (int i = 0; i < 16; i++)
            {
                // Циклический сдвиг влево
                left = LeftShift28(left, DESTables.SHIFTS[i]);
                right = LeftShift28(right, DESTables.SHIFTS[i]);

                // Объединяем половины (56 бит) и применяем PC2 (56 бит -> 48 бит)
                byte[] combined = Combine28Bits(left, right);
                roundKeys[i] = BitPermutation.PermutationBytes(combined, DESTables.PC2, false, false);
            }

            return roundKeys;
        }

        private uint Get28Bits(byte[] data, int startBit)
        {
            uint result = 0;
            for (int i = 0; i < 28; i++)
            {
                int byteIndex = (startBit + i) / 8;
                int bitIndex = (startBit + i) % 8;
                if (byteIndex < data.Length)
                {
                    bool bitValue = (data[byteIndex] & (1 << (7 - bitIndex))) != 0;
                    if (bitValue)
                        result |= (1u << (27 - i));
                }
            }
            return result;
        }

        private byte[] Combine28Bits(uint left, uint right)
        {
            byte[] result = new byte[7]; // 56 бит = 7 байт
            for (int i = 0; i < 28; i++)
            {
                bool leftBit = (left & (1u << (27 - i))) != 0;
                bool rightBit = (right & (1u << (27 - i))) != 0;
                
                int byteIndex = i / 8;
                int bitIndex = i % 8;
                
                if (leftBit)
                    result[byteIndex] |= (byte)(1 << (7 - bitIndex));
                
                if (rightBit)
                    result[byteIndex + 3] |= (byte)(1 << (7 - (i % 8))); // right starts at bit 28
            }
            return result;
        }

        private uint LeftShift28(uint value, int shifts)
        {
            return ((value << shifts) | (value >> (28 - shifts))) & 0x0FFFFFFF;
        }
    }
}
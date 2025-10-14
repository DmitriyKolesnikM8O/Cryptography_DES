using System;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    public class DEALKeyScheduler : IKeyScheduler
    {
        public enum KeyType
        {
            KEY_SIZE_128,  // 128 бит
            KEY_SIZE_192,  // 192 бита  
            KEY_SIZE_256   // 256 бит
        }

        private readonly KeyType _keyType;
        private readonly int _rounds;

        public DEALKeyScheduler(KeyType keyType)
        {
            _keyType = keyType;
            _rounds = keyType switch
            {
                KeyType.KEY_SIZE_128 => 6,
                KeyType.KEY_SIZE_192 => 8,
                KeyType.KEY_SIZE_256 => 8,
                _ => throw new ArgumentException("Invalid key type")
            };
        }

        public byte[][] ExpandKey(byte[] inputKey)
        {
            ValidateKeySize(inputKey);

            byte[][] roundKeys = new byte[_rounds][];

            switch (_keyType)
            {
                case KeyType.KEY_SIZE_128:
                    ExpandKey128(inputKey, roundKeys);
                    break;
                case KeyType.KEY_SIZE_192:
                    ExpandKey192(inputKey, roundKeys);
                    break;
                case KeyType.KEY_SIZE_256:
                    ExpandKey256(inputKey, roundKeys);
                    break;
            }

            return roundKeys;
        }

        private void ValidateKeySize(byte[] key)
        {
            int expectedSize = _keyType switch
            {
                KeyType.KEY_SIZE_128 => 16,
                KeyType.KEY_SIZE_192 => 24,
                KeyType.KEY_SIZE_256 => 32,
                _ => throw new InvalidOperationException("Unknown key type")
            };

            if (key.Length != expectedSize)
                throw new ArgumentException($"Key must be {expectedSize} bytes for {_keyType}");
        }

        private void ExpandKey128(byte[] key, byte[][] roundKeys)
        {
            // DEAL-128: 6 раундов, каждый раундовый ключ = 64 бита (8 байт)
            for (int i = 0; i < 6; i++)
            {
                roundKeys[i] = new byte[8];
                
                if (i < 4)
                {
                    // Первые 4 ключа берутся непосредственно из исходного ключа
                    Array.Copy(key, i * 4, roundKeys[i], 0, 4);
                    Array.Copy(key, (i * 4 + 4) % 16, roundKeys[i], 4, 4);
                }
                else
                {
                    // Последние 2 ключа - производные
                    Array.Copy(key, (i - 4) * 4, roundKeys[i], 0, 4);
                    Array.Copy(key, ((i - 4) * 4 + 8) % 16, roundKeys[i], 4, 4);
                }
            }
        }

        private void ExpandKey192(byte[] key, byte[][] roundKeys)
        {
            // DEAL-192: 8 раундов
            for (int i = 0; i < 8; i++)
            {
                roundKeys[i] = new byte[8];
                
                if (i < 6)
                {
                    // Ключи берутся из исходного ключа
                    int offset = (i * 4) % 24;
                    Array.Copy(key, offset, roundKeys[i], 0, 4);
                    Array.Copy(key, (offset + 8) % 24, roundKeys[i], 4, 4);
                }
                else
                {
                    // Производные ключи для последних раундов
                    int baseIndex = (i - 6) * 4;
                    Array.Copy(key, baseIndex, roundKeys[i], 0, 4);
                    Array.Copy(key, (baseIndex + 12) % 24, roundKeys[i], 4, 4);
                }
            }
        }

        private void ExpandKey256(byte[] key, byte[][] roundKeys)
        {
            // DEAL-256: 8 раундов
            for (int i = 0; i < 8; i++)
            {
                roundKeys[i] = new byte[8];
                
                // Ключи берутся непосредственно из 256-битного ключа
                int offset = (i * 8) % 32;
                Array.Copy(key, offset, roundKeys[i], 0, 8);
            }
        }
    }
}
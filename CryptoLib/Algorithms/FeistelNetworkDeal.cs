using System;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    /// <summary>
    /// Специализированная сеть Фейстеля для алгоритма DEAL
    /// DEAL работает с блоками 128 бит (16 байт) и использует DES как раундовую функцию
    /// </summary>
    public class FeistelNetworkDEAL : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler;
        private readonly IFeistelFunction _feistelFunction;
        private readonly int _rounds;
        private byte[][] _roundKeys;
        private bool _keysSet = false;

        public FeistelNetworkDEAL(
            IKeyScheduler keyScheduler,
            IFeistelFunction feistelFunction,
            int rounds)
        {
            _keyScheduler = keyScheduler ?? throw new ArgumentNullException(nameof(keyScheduler));
            _feistelFunction = feistelFunction ?? throw new ArgumentNullException(nameof(feistelFunction));
            _rounds = rounds > 0 ? rounds : throw new ArgumentException("Количество раундов должно быть положительным", nameof(rounds));
        }

        public int BlockSize => 16; // DEAL работает с блоками 128 бит (16 байт)

        public int KeySize => throw new NotImplementedException("KeySize определяется в DEALAlgorithm");

        public void SetRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            
            // DEAL поддерживает ключи 16, 24, 32 байта
            if (key.Length != 16 && key.Length != 24 && key.Length != 32)
                throw new ArgumentException("DEAL key must be 16, 24, or 32 bytes");

            _roundKeys = _keyScheduler.ExpandKey(key);
            _keysSet = true;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Раундовые ключи не установлены. Вызовите SetRoundKeys сначала.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize)
                throw new ArgumentException($"Размер блока должен быть {BlockSize} байт для DEAL");

            // Разделяем блок на две половины по 64 бита (8 байт)
            int halfSize = 8; // 64 бита
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            // Выполняем раунды Фейстеля
            for (int round = 0; round < _rounds; round++)
            {
                byte[] temp = right;
                
                // Применяем Feistel функцию к правой половине с текущим раундовым ключом
                byte[] feistelResult = _feistelFunction.Execute(right, _roundKeys[round]);
                
                // XOR левой половины с результатом Feistel функции
                right = XorBlocks(left, feistelResult);
                left = temp;
            }

            // Объединяем половины (после последнего раунда не меняем местами)
            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);

            return result;
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Раундовые ключи не установлены. Вызовите SetRoundKeys сначала.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize)
                throw new ArgumentException($"Размер блока должен быть {BlockSize} байт для DEAL");

            // Разделяем блок на две половины по 64 бита (8 байт)
            int halfSize = 8; // 64 бита
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            // Выполняем раунды Фейстеля в обратном порядке
            for (int round = _rounds - 1; round >= 0; round--)
            {
                byte[] temp = left;
                
                // Применяем Feistel функцию к левой половине с текущим раундовым ключом
                byte[] feistelResult = _feistelFunction.Execute(left, _roundKeys[round]);
                
                // XOR правой половины с результатом Feistel функции
                left = XorBlocks(right, feistelResult);
                right = temp;
            }

            // Объединяем половины
            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);

            return result;
        }

        /// <summary>
        /// Выполняет операцию XOR между двумя блоками данных
        /// </summary>
        private byte[] XorBlocks(byte[] block1, byte[] block2)
        {
            if (block1.Length != block2.Length)
                throw new ArgumentException("Блоки должны быть одинакового размера");

            byte[] result = new byte[block1.Length];
            for (int i = 0; i < block1.Length; i++)
            {
                result[i] = (byte)(block1[i] ^ block2[i]);
            }
            return result;
        }
    }
}
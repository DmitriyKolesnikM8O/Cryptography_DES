using System;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms
{
    public class FeistelNetwork : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler;
        private readonly IFeistelFunction _feistelFunction;
        private readonly int _rounds;
        private byte[][] _roundKeys = default!;
        private bool _keysSet = false;

        // === БУФЕРЫ, ВЫНЕСЕННЫЕ В ПОЛЯ КЛАССА ===
        private readonly byte[] _left;
        private readonly byte[] _right;
        private readonly byte[] _temp; // Для безопасного обмена L и R
        private readonly byte[] _finalResult;
        private readonly int _halfSize;

        public FeistelNetwork(
            IKeyScheduler keyScheduler,
            IFeistelFunction feistelFunction,
            int rounds)
        {
            _keyScheduler = keyScheduler ?? throw new ArgumentNullException(nameof(keyScheduler));
            _feistelFunction = feistelFunction ?? throw new ArgumentNullException(nameof(feistelFunction));
            _rounds = rounds > 0 ? rounds : throw new ArgumentException("Количество раундов должно быть положительным", nameof(rounds));
        
            // === ИНИЦИАЛИЗАЦИЯ БУФЕРОВ ОДИН РАЗ В КОНСТРУКТОРЕ ===
            _halfSize = this.BlockSize / 2;
            _left = new byte[_halfSize];
            _right = new byte[_halfSize];
            _temp = new byte[_halfSize];
            _finalResult = new byte[this.BlockSize];
        }

        // Остальные свойства и SetRoundKeys остаются без изменений
        public int BlockSize => 8;
        public int KeySize => 8;

        public void SetRoundKeys(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != KeySize)
                throw new ArgumentException($"Ключ должен быть {KeySize} байт");

            _roundKeys = _keyScheduler.ExpandKey(key);
            _keysSet = true;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Раундовые ключи не установлены.");
            if (block == null || block.Length != BlockSize)
                throw new ArgumentException($"Размер блока должен быть {BlockSize} байт");

            // Используем поля-буферы, НЕ создавая новую память
            Array.Copy(block, 0, _left, 0, _halfSize);
            Array.Copy(block, _halfSize, _right, 0, _halfSize);

            for (int round = 0; round < _rounds; round++)
            {
                // Сохраняем левую часть во временный буфер
                Array.Copy(_left, 0, _temp, 0, _halfSize);

                // Новая левая часть = старая правая часть
                Array.Copy(_right, 0, _left, 0, _halfSize);

                // Вычисляем результат F-функции
                byte[] feistelResult = _feistelFunction.Execute(_right, _roundKeys[round]);
                
                // Новая правая часть = старая левая (из temp) XOR результат F-функции
                XorBlocks(_temp, feistelResult, _right); // Пишем результат в _right
            }
            
            // Объединяем половины в финальный буфер
            Array.Copy(_left, 0, _finalResult, 0, _halfSize);
            Array.Copy(_right, 0, _finalResult, _halfSize, _halfSize);

            return (byte[])_finalResult.Clone();
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Раундовые ключи не установлены.");
            if (block == null || block.Length != BlockSize)
                throw new ArgumentException($"Размер блока должен быть {BlockSize} байт");

            // Используем поля-буферы
            Array.Copy(block, 0, _left, 0, _halfSize);
            Array.Copy(block, _halfSize, _right, 0, _halfSize);

            for (int round = _rounds - 1; round >= 0; round--)
            {
                // Сохраняем правую часть во временный буфер
                Array.Copy(_right, 0, _temp, 0, _halfSize);

                // Новая правая часть = старая левая часть
                Array.Copy(_left, 0, _right, 0, _halfSize);
                
                // Вычисляем результат F-функции
                byte[] feistelResult = _feistelFunction.Execute(_left, _roundKeys[round]);

                // Новая левая часть = старая правая (из temp) XOR результат F-функции
                XorBlocks(_temp, feistelResult, _left); // Пишем результат в _left
            }

            Array.Copy(_left, 0, _finalResult, 0, _halfSize);
            Array.Copy(_right, 0, _finalResult, _halfSize, _halfSize);

            return (byte[])_finalResult.Clone();
        }

        // ПЕРЕПИСАННЫЙ МЕТОД: не возвращает новый массив, а записывает результат в существующий
        private void XorBlocks(byte[] block1, byte[] block2, byte[] result)
        {
            for (int i = 0; i < block1.Length; i++)
            {
                result[i] = (byte)(block1[i] ^ block2[i]);
            }
        }
    }
}
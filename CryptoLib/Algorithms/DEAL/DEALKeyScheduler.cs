using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    /// <summary>
    /// Реализует планировщик ключей для алгоритма DEAL.
    /// Отвечает за генерацию (расширение) набора 64-битных раундовых ключей (для использования в DES)
    /// из основного ключа DEAL, который может иметь размер 128, 192 или 256 бит.
    /// </summary>
    public class DEALKeyScheduler : IKeyScheduler
    {
        /// <summary>
        /// Перечисление, определяющее поддерживаемые размеры ключа для алгоритма DEAL.
        /// </summary>
        public enum KeyType
        {
            KEY_SIZE_128,
            KEY_SIZE_192,
            KEY_SIZE_256
        }

        private readonly KeyType _keyType;
        private readonly int _rounds;

        /// <summary>
        /// Инициализирует новый экземпляр планировщика ключей DEAL для указанного типа ключа.
        /// </summary>
        /// <param name="keyType">Тип (размер) ключа, для которого будет выполняться генерация раундовых ключей.</param>
        /// <exception cref="ArgumentException">Вызывается, если указан недопустимый тип ключа.</exception>
        public DEALKeyScheduler(KeyType keyType)
        {
            _keyType = keyType;
            _rounds = keyType switch
            {
                KeyType.KEY_SIZE_128 => 6,
                KeyType.KEY_SIZE_192 => 6,
                KeyType.KEY_SIZE_256 => 8,
                _ => throw new ArgumentException("Invalid key type")
            };
        }

        /// <summary>
        /// Генерирует набор раундовых ключей из предоставленного основного ключа.
        /// </summary>
        /// <param name="inputKey">Основной ключ DEAL (16, 24 или 32 байта).</param>
        /// <returns>Зубчатый массив, где каждый элемент - это 64-битный (8-байтный) раундовый ключ.</returns>
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

        /// <summary>
        /// Проверяет, соответствует ли длина предоставленного ключа типу, указанному в конструкторе.
        /// </summary>
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

        /// <summary>
        /// Генерирует 6 раундовых ключей из 128-битного основного ключа.
        /// </summary>
        private void ExpandKey128(byte[] key, byte[][] roundKeys)
        {

            for (int i = 0; i < 6; i++)
            {
                roundKeys[i] = new byte[8];

                if (i < 4)
                {

                    Array.Copy(key, i * 4, roundKeys[i], 0, 4);
                    Array.Copy(key, (i * 4 + 4) % 16, roundKeys[i], 4, 4);
                }
                else
                {

                    Array.Copy(key, (i - 4) * 4, roundKeys[i], 0, 4);
                    Array.Copy(key, ((i - 4) * 4 + 8) % 16, roundKeys[i], 4, 4);
                }
            }
        }

        /// <summary>
        /// Генерирует 6 раундовых ключей из 192-битного основного ключа.
        /// </summary>
        private void ExpandKey192(byte[] key, byte[][] roundKeys)
        {
            
            for (int i = 0; i < 6; i++)
            {
                roundKeys[i] = new byte[8];
                
                int offset = i * 4 % 24;
                Array.Copy(key, offset, roundKeys[i], 0, 4);
                Array.Copy(key, (offset + 8) % 24, roundKeys[i], 4, 4);
            }
        }

        /// <summary>
        /// Генерирует 8 раундовых ключей из 256-битного основного ключа.
        /// </summary>
        private void ExpandKey256(byte[] key, byte[][] roundKeys)
        {

            for (int i = 0; i < 8; i++)
            {
                roundKeys[i] = new byte[8];

                int offset = i * 8 % 32;
                Array.Copy(key, offset, roundKeys[i], 0, 8);
            }
        }
    }
}
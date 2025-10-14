using System;
using CryptoLib.Algorithms.DES;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    /// <summary>
    /// Адаптер для использования DES алгоритма в качестве раундовой функции F в DEAL
    /// </summary>
    public class DESAdapter : IFeistelFunction
    {
        private readonly DESAlgorithm _des;

        public DESAdapter()
        {
            _des = new DESAlgorithm();
        }

        /// <summary>
        /// Выполняет раундовую функцию F используя DES алгоритм
        /// </summary>
        /// <param name="inputBlock">Входной блок (64 бита для DEAL)</param>
        /// <param name="roundKey">Раундовый ключ (64 бита)</param>
        /// <returns>Результат раундовой функции (64 бита)</returns>
        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            if (inputBlock.Length != 8) // 64 бита
                throw new ArgumentException("Input block must be 64 bits (8 bytes) for DEAL");
            if (roundKey.Length != 8) // 64 бита
                throw new ArgumentException("Round key must be 64 bits (8 bytes) for DEAL");

            // Устанавливаем ключ в DES
            _des.SetRoundKeys(roundKey);
            
            // Выполняем шифрование DES
            return _des.EncryptBlock(inputBlock);
        }
    }
}
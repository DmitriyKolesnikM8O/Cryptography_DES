using System;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    public class DEALFeistelFunction : IFeistelFunction
    {
        private readonly DESAdapter _desAdapter;

        public DEALFeistelFunction()
        {
            _desAdapter = new DESAdapter();
        }

        /// <summary>
        /// Выполняет раундовую функцию F для DEAL
        /// </summary>
        /// <param name="inputBlock">Входной блок (64 бита - правая половина)</param>
        /// <param name="roundKey">Раундовый ключ (64 бита)</param>
        /// <returns>Результат раундовой функции (64 бита)</returns>
        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            // В DEAL раундовая функция F - это просто DES шифрование
            return _desAdapter.Execute(inputBlock, roundKey);
        }
    }
}
using System;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    public class DEALFeistelFunction : IFeistelFunction
    {
        // Конструктор теперь пуст. Мы не храним общее состояние.
        public DEALFeistelFunction()
        {
        }

        /// <summary>
        /// Выполняет раундовую функцию F для DEAL.
        /// Этот метод теперь полностью потокобезопасен.
        /// </summary>
        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            // Создаем новый, "чистый" адаптер для каждого вызова.
            // Это предотвращает состояние гонки, когда несколько потоков
            // вызывают этот метод одновременно.
            var localDesAdapter = new DESAdapter();
            
            // В DEAL раундовая функция F - это просто DES шифрование
            return localDesAdapter.Execute(inputBlock, roundKey);
        }
    }
}
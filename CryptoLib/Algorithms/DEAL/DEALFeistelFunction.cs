using System;
using System.Threading;
using CryptoLib.Algorithms.DES; // <-- Убедитесь, что этот using есть
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    public class DEALFeistelFunction : IFeistelFunction
    {
        // Создаем пул потоко-локальных экземпляров DESAlgorithm.
        // Каждый поток получит свой собственный, быстрый, stateful экземпляр.
        private readonly ThreadLocal<DESAlgorithm> _threadLocalDes;

        public DEALFeistelFunction()
        {
            _threadLocalDes = new ThreadLocal<DESAlgorithm>(() => new DESAlgorithm());
        }

        public byte[] Execute(byte[] inputBlock, byte[] roundKey)
        {
            // 1. Получаем экземпляр DES, принадлежащий текущему потоку.
            DESAlgorithm des = _threadLocalDes.Value!;
            
            // 2. Используем его. Это быстро и потокобезопасно.
            des.SetRoundKeys(roundKey);
            return des.EncryptBlock(inputBlock);
        }
    }
}
using System;
using CryptoLib.Algorithms;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DES
{
    public class DESAlgorithm : ISymmetricCipher
    {
        private readonly FeistelNetwork _feistelNetwork;
        private bool _keysSet = false;

        public DESAlgorithm()
        {
            // Используем FeistelNetwork из задания 3
            var keyScheduler = new DESKeyScheduler();
            var feistelFunction = new DESFeistelFunction();
            _feistelNetwork = new FeistelNetwork(keyScheduler, feistelFunction, 16);
        }

        public int BlockSize => 8; // 64 бита
        public int KeySize => 8;   // 64 бита

        public void SetRoundKeys(byte[] key)
        {
            if (key.Length != KeySize)
                throw new ArgumentException($"DES key must be {KeySize} bytes");

            _feistelNetwork.SetRoundKeys(key);
            _keysSet = true;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            // Используем FeistelNetwork для шифрования
            return _feistelNetwork.EncryptBlock(block);
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes");

            // Используем FeistelNetwork для дешифрования
            return _feistelNetwork.DecryptBlock(block);
        }
    }
}
using System;
using CryptoLib.Interfaces;

namespace CryptoLib.Algorithms.DEAL
{
    public class DEALAlgorithm : ISymmetricCipher
    {
        private readonly FeistelNetworkDEAL _feistelNetwork;
        private readonly DEALKeyScheduler.KeyType _keyType;
        private bool _keysSet = false;

        public DEALAlgorithm(DEALKeyScheduler.KeyType keyType = DEALKeyScheduler.KeyType.KEY_SIZE_128)
        {
            _keyType = keyType;
            
            // Создаем специализированную сеть Фейстеля для DEAL
            var keyScheduler = new DEALKeyScheduler(keyType);
            var feistelFunction = new DEALFeistelFunction();
            
            int rounds = keyType switch
            {
                DEALKeyScheduler.KeyType.KEY_SIZE_128 => 6,
                DEALKeyScheduler.KeyType.KEY_SIZE_192 => 8,
                DEALKeyScheduler.KeyType.KEY_SIZE_256 => 8,
                _ => throw new ArgumentException("Invalid key type")
            };

            _feistelNetwork = new FeistelNetworkDEAL(keyScheduler, feistelFunction, rounds);
        }

        public int BlockSize => 16; // 128 бит для DEAL

        public int KeySize => _keyType switch
        {
            DEALKeyScheduler.KeyType.KEY_SIZE_128 => 16,
            DEALKeyScheduler.KeyType.KEY_SIZE_192 => 24,
            DEALKeyScheduler.KeyType.KEY_SIZE_256 => 32,
            _ => throw new InvalidOperationException("Unknown key type")
        };

        public void SetRoundKeys(byte[] key)
        {
            if (key.Length != KeySize)
                throw new ArgumentException($"DEAL key must be {KeySize} bytes for {_keyType}");

            _feistelNetwork.SetRoundKeys(key);
            _keysSet = true;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes for DEAL");

            return _feistelNetwork.EncryptBlock(block);
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (!_keysSet)
                throw new InvalidOperationException("Round keys not set. Call SetRoundKeys first.");
            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes for DEAL");

            return _feistelNetwork.DecryptBlock(block);
        }
    }
}
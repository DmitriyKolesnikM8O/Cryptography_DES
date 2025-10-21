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

        public FeistelNetwork(
            IKeyScheduler keyScheduler,
            IFeistelFunction feistelFunction,
            int rounds)
        {
            _keyScheduler = keyScheduler;
            _feistelFunction = feistelFunction;
            _rounds = rounds;
        }

        public int BlockSize => 8;
        public int KeySize => 8;

        public void SetRoundKeys(byte[] key)
        {
            _roundKeys = _keyScheduler.ExpandKey(key);
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (_roundKeys == null) throw new InvalidOperationException("Round keys not set.");

            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int round = 0; round < _rounds; round++)
            {
                byte[] tempLeft = (byte[])left.Clone();
                left = right;
                byte[] feistelResult = _feistelFunction.Execute(right, _roundKeys[round]);
                right = XorBlocks(tempLeft, feistelResult);
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);
            return result;
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (_roundKeys == null) throw new InvalidOperationException("Round keys not set.");

            int halfSize = BlockSize / 2;
            byte[] left = new byte[halfSize];
            byte[] right = new byte[halfSize];
            Array.Copy(block, 0, left, 0, halfSize);
            Array.Copy(block, halfSize, right, 0, halfSize);

            for (int round = _rounds - 1; round >= 0; round--)
            {
                byte[] tempRight = (byte[])right.Clone();
                right = left;
                byte[] feistelResult = _feistelFunction.Execute(left, _roundKeys[round]);
                left = XorBlocks(tempRight, feistelResult);
            }

            byte[] result = new byte[BlockSize];
            Array.Copy(left, 0, result, 0, halfSize);
            Array.Copy(right, 0, result, halfSize, halfSize);
            return result;
        }
        
        private byte[] XorBlocks(byte[] block1, byte[] block2)
        {
            byte[] result = new byte[block1.Length];
            for (int i = 0; i < block1.Length; i++)
            {
                result[i] = (byte)(block1[i] ^ block2[i]);
            }
            return result;
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.Interfaces;
using CryptoLib.Algorithms.DES;

namespace CryptoLib.Modes
{
    public class CipherContext
    {
        private readonly ISymmetricCipher _algorithm;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[] _initializationVector;
        private readonly int _blockSize;

        public CipherContext(
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            byte[] initializationVector = null,
            params KeyValuePair<string, object>[] additionalParameters)
        {
            _mode = mode;
            _padding = padding;
            _initializationVector = initializationVector;

            _algorithm = CreateAlgorithm(additionalParameters);
            _algorithm.SetRoundKeys(key);
            _blockSize = _algorithm.BlockSize;

            ValidateParameters();
        }

        private ISymmetricCipher CreateAlgorithm(KeyValuePair<string, object>[] additionalParameters)
        {
            
            return new DESAlgorithm();
        }

        private void ValidateParameters()
        {
            if (_mode != CipherMode.ECB && _initializationVector == null)
            {
                throw new ArgumentException($"Режим {_mode} требует вектор инициализации");
            }

            if (_initializationVector != null && _initializationVector.Length != _blockSize)
            {
                throw new ArgumentException(
                    $"Размер вектора инициализации ({_initializationVector.Length}) " +
                    $"должен совпадать с размером блока ({_blockSize})");
            }
        }

        public async Task EncryptAsync(byte[] inputData, byte[] output)
        {
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            if (output == null) throw new ArgumentNullException(nameof(output));

            await Task.Run(() =>
            {
                byte[] paddedData = ApplyPadding(inputData, _blockSize);
                byte[] encryptedData = EncryptData(paddedData);
                
                int copyLength = Math.Min(encryptedData.Length, output.Length);
                Array.Copy(encryptedData, output, copyLength);
            });
        }

        public async Task DecryptAsync(byte[] inputData, byte[] output)
        {
            if (inputData == null) throw new ArgumentNullException(nameof(inputData));
            if (output == null) throw new ArgumentNullException(nameof(output));

            await Task.Run(() =>
            {
                byte[] decryptedData = DecryptData(inputData);
                byte[] unpaddedData = RemovePadding(decryptedData);
                
                int copyLength = Math.Min(unpaddedData.Length, output.Length);
                Array.Copy(unpaddedData, output, copyLength);
            });
        }

        public async Task EncryptAsync(string inputFilePath, string outputFilePath)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            byte[] inputData = await File.ReadAllBytesAsync(inputFilePath);
            byte[] encryptedData = await EncryptDataAsync(inputData);
            await File.WriteAllBytesAsync(outputFilePath, encryptedData);
        }

        public async Task DecryptAsync(string inputFilePath, string outputFilePath)
        {
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            byte[] inputData = await File.ReadAllBytesAsync(inputFilePath);
            byte[] decryptedData = await DecryptDataAsync(inputData);
            await File.WriteAllBytesAsync(outputFilePath, decryptedData);
        }

        private async Task<byte[]> EncryptDataAsync(byte[] data)
        {
            return await Task.Run(() =>
            {
                byte[] paddedData = ApplyPadding(data, _blockSize);
                return EncryptData(paddedData);
            });
        }

        private async Task<byte[]> DecryptDataAsync(byte[] data)
        {
            return await Task.Run(() =>
            {
                byte[] decryptedData = DecryptData(data);
                return RemovePadding(decryptedData);
            });
        }

        private byte[] EncryptData(byte[] data)
        {
            return _mode switch
            {
                CipherMode.ECB => EncryptECB(data),
                CipherMode.CBC => EncryptCBC(data),
                CipherMode.PCBC => EncryptPCBC(data),
                CipherMode.CFB => EncryptCFB(data),
                CipherMode.OFB => EncryptOFB(data),
                CipherMode.CTR => EncryptCTR(data),
                CipherMode.RandomDelta => EncryptRandomDelta(data),
                _ => throw new NotSupportedException($"Режим {_mode} не реализован")
            };
        }

        private byte[] DecryptData(byte[] data)
        {
            return _mode switch
            {
                CipherMode.ECB => DecryptECB(data),
                CipherMode.CBC => DecryptCBC(data),
                CipherMode.PCBC => DecryptPCBC(data),
                CipherMode.CFB => DecryptCFB(data),
                CipherMode.OFB => DecryptOFB(data),
                CipherMode.CTR => DecryptCTR(data),
                CipherMode.RandomDelta => DecryptRandomDelta(data),
                _ => throw new NotSupportedException($"Режим {_mode} не реализован")
            };
        }

        private byte[] EncryptECB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            
            Parallel.For(0, data.Length / blockSize, i =>
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);
                
                byte[] encryptedBlock = _algorithm.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
            });
            
            return result;
        }

        private byte[] DecryptECB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            
            Parallel.For(0, data.Length / blockSize, i =>
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);
                
                byte[] decryptedBlock = _algorithm.DecryptBlock(block);
                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
            });
            
            return result;
        }

        private byte[] EncryptCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = (byte[])_initializationVector.Clone();
            
            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);
                
                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= previousBlock[j];
                }
                
                byte[] encryptedBlock = _algorithm.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
                previousBlock = encryptedBlock;
            }
            
            return result;
        }

        private byte[] DecryptCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = (byte[])_initializationVector.Clone();
            
            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);
                
                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);
                
                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= previousBlock[j];
                }
                
                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
                previousBlock = encryptedBlock;
            }
            
            return result;
        }

        private byte[] EncryptPCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousInput = (byte[])_initializationVector.Clone();
            byte[] previousOutput = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);
                }

                byte[] encryptedBlock = _algorithm.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);

                previousInput = (byte[])block.Clone();
                previousOutput = (byte[])encryptedBlock.Clone();
            }

            return result;
        }

        private byte[] DecryptPCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousInput = (byte[])_initializationVector.Clone();
            byte[] previousOutput = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);

                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);
                }

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);

                previousInput = (byte[])decryptedBlock.Clone();
                previousOutput = (byte[])encryptedBlock.Clone();
            }

            return result;
        }

        private byte[] EncryptCFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);

                byte[] encryptedFeedback = _algorithm.EncryptBlock(feedback);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(block[j] ^ encryptedFeedback[j]);
                }

                Array.Copy(result, offset, feedback, 0, blockSize);
            }

            return result;
        }

        private byte[] DecryptCFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                byte[] encryptedFeedback = _algorithm.EncryptBlock(feedback);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(encryptedBlock[j] ^ encryptedFeedback[j]);
                }

                Array.Copy(encryptedBlock, 0, feedback, 0, blockSize);
            }

            return result;
        }

        private byte[] EncryptOFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);

                feedback = _algorithm.EncryptBlock(feedback);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(block[j] ^ feedback[j]);
                }
            }

            return result;
        }

        private byte[] DecryptOFB(byte[] data)
        {
            return EncryptOFB(data);
        }

        private byte[] EncryptCTR(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] counter = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);

                byte[] encryptedCounter = _algorithm.EncryptBlock(counter);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(block[j] ^ encryptedCounter[j]);
                }

                IncrementCounter(counter);
            }

            return result;
        }

        private byte[] DecryptCTR(byte[] data)
        {
            return EncryptCTR(data);
        }

        private byte[] EncryptRandomDelta(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] delta = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);

                Random random = new Random(BitConverter.ToInt32(delta, 0));
                random.NextBytes(delta);

                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= delta[j];
                }

                byte[] encryptedBlock = _algorithm.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
            }

            return result;
        }

        private byte[] DecryptRandomDelta(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] delta = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);

                Random random = new Random(BitConverter.ToInt32(delta, 0));
                random.NextBytes(delta);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(decryptedBlock[j] ^ delta[j]);
                }
            }

            return result;
        }

        private void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
        }

        private byte[] ApplyPadding(byte[] data, int blockSize)
        {
            int paddingLength = blockSize - (data.Length % blockSize);
            if (paddingLength == blockSize)
                return data;
            
            return _padding switch
            {
                PaddingMode.Zeros => ApplyZerosPadding(data, paddingLength),
                PaddingMode.PKCS7 => ApplyPKCS7Padding(data, paddingLength),
                PaddingMode.ANSIX923 => ApplyAnsiX923Padding(data, paddingLength),
                PaddingMode.ISO10126 => ApplyIso10126Padding(data, paddingLength),
                _ => throw new NotSupportedException($"Режим паддинга {_padding} не поддерживается")
            };
        }

        private byte[] RemovePadding(byte[] data)
        {

            if (data.Length == 0 || data.Length % _blockSize != 0)
                return data;
            

            return _padding switch
            {
                PaddingMode.Zeros => RemoveZerosPadding(data),
                PaddingMode.PKCS7 => RemovePKCS7Padding(data),
                PaddingMode.ANSIX923 => RemoveAnsiX923Padding(data),
                PaddingMode.ISO10126 => RemoveIso10126Padding(data),
                _ => throw new NotSupportedException($"Режим паддинга {_padding} не поддерживается")
            };
        }

        private byte[] ApplyZerosPadding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            return result;
        }

        private byte[] RemoveZerosPadding(byte[] data)
        {
            return data;
        }

        private byte[] ApplyPKCS7Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            for (int i = data.Length; i < result.Length; i++)
            {
                result[i] = (byte)paddingLength;
            }
            return result;
        }

        private byte[] RemovePKCS7Padding(byte[] data)
        {
            if (data.Length == 0) return data;
            
            byte paddingValue = data[^1];
            if (paddingValue == 0 || paddingValue > data.Length) return data;
            
            for (int i = data.Length - paddingValue; i < data.Length; i++)
            {
                if (data[i] != paddingValue)
                    return data;
            }
            
            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }

        private byte[] ApplyAnsiX923Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            result[^1] = (byte)paddingLength;
            return result;
        }

        private byte[] RemoveAnsiX923Padding(byte[] data)
        {
            if (data.Length == 0) return data;
            
            byte paddingValue = data[^1];
            if (paddingValue == 0 || paddingValue > data.Length) return data;
            
            for (int i = data.Length - paddingValue; i < data.Length - 1; i++)
            {
                if (data[i] != 0)
                    return data;
            }
            
            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }

        private byte[] ApplyIso10126Padding(byte[] data, int paddingLength)
        {
            byte[] result = new byte[data.Length + paddingLength];
            Array.Copy(data, result, data.Length);
            
            Random random = new Random();
            for (int i = data.Length; i < result.Length - 1; i++)
            {
                result[i] = (byte)random.Next(256);
            }
            
            result[^1] = (byte)paddingLength;
            return result;
        }

        private byte[] RemoveIso10126Padding(byte[] data)
        {
            if (data.Length == 0) return data;
            
            byte paddingValue = data[^1];
            if (paddingValue == 0 || paddingValue > data.Length) return data;
            
            byte[] result = new byte[data.Length - paddingValue];
            Array.Copy(data, result, result.Length);
            return result;
        }
    }
}
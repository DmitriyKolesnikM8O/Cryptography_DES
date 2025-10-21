using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.Interfaces;
using CryptoLib.Algorithms.DES;
using CryptoLib.Algorithms.DEAL;

namespace CryptoLib.Modes
{
    public class CipherContext
    {
        private readonly ISymmetricCipher _algorithm;
        private readonly CipherMode _mode;

        private readonly object _algorithmLock = new object();
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

            _algorithm = CreateAlgorithm(key, additionalParameters);
            _algorithm.SetRoundKeys(key);
            _blockSize = _algorithm.BlockSize;

            ValidateParameters();
        }

        private ISymmetricCipher CreateAlgorithm(byte[] key, KeyValuePair<string, object>[] additionalParameters)
        {
            // Сначала проверяем явное указание алгоритма в дополнительных параметрах
            if (additionalParameters != null)
            {
                var algorithmParam = additionalParameters.FirstOrDefault(p => p.Key == "Algorithm");
                if (!algorithmParam.Equals(default(KeyValuePair<string, object>)))
                {
                    var algorithmValue = algorithmParam.Value.ToString();
                    
                    if (algorithmValue.Contains("DEAL"))
                    {
                        // Для DEAL определяем тип по размеру ключа
                        return key.Length switch
                        {
                            16 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_128),
                            24 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_192),
                            32 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_256),
                            _ => throw new ArgumentException($"Unsupported DEAL key size: {key.Length} bytes")
                        };
                    }
                    else if (algorithmValue.Contains("DES"))
                    {
                        return new DESAlgorithm();
                    }
                    
                    return algorithmValue switch
                    {
                        "DEAL" => new DEALAlgorithm(), // по умолчанию 128-bit
                        "DES" => new DESAlgorithm(),
                        _ => throw new ArgumentException($"Unsupported algorithm: {algorithmValue}")
                    };
                }
            }

            // Автоопределение по размеру ключа
            return key.Length switch
            {
                8 => new DESAlgorithm(),
                16 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_128),
                24 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_192),
                32 => new DEALAlgorithm(DEALKeyScheduler.KeyType.KEY_SIZE_256),
                _ => throw new ArgumentException($"Unsupported key size: {key.Length} bytes")
            };
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
                
                byte[] encryptedBlock;
                lock (_algorithmLock)
                {
                    encryptedBlock = _algorithm.EncryptBlock(block);
                }
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
                
                byte[] decryptedBlock;
                lock (_algorithmLock)
                {
                    decryptedBlock = _algorithm.DecryptBlock(block);
                }
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

        // private byte[] DecryptCBC(byte[] data)
        // {
        //     int blockSize = _blockSize;
        //     int blockCount = data.Length / blockSize;
        //     byte[] result = new byte[data.Length];

        //     // Получаем все зашифрованные блоки
        //     byte[][] encryptedBlocks = new byte[blockCount][];
        //     for (int i = 0; i < blockCount; i++)
        //     {
        //         encryptedBlocks[i] = new byte[blockSize];
        //         Array.Copy(data, i * blockSize, encryptedBlocks[i], 0, blockSize);
        //     }


        //     byte[][] decryptedBlocks = new byte[blockCount][];
        //     var options = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };
        //     var decryptLock = new object(); 

        //     Parallel.For(0, blockCount, options, i =>
        //     {
        //         // Console.WriteLine($"Поток {Thread.CurrentThread.ManagedThreadId} обрабатывает блок {i}");
        //         byte[] block;
        //         lock (decryptLock)
        //         {
        //             block = (byte[])_algorithm.DecryptBlock(encryptedBlocks[i]).Clone();
        //         }
        //         decryptedBlocks[i] = block;
        //     });

        //     // Последовательно применяем XOR
        //     byte[] previousCipherBlock = (byte[])_initializationVector.Clone();
        //     for (int i = 0; i < blockCount; i++)
        //     {
        //         for (int j = 0; j < blockSize; j++)
        //         {
        //             result[i * blockSize + j] = (byte)(decryptedBlocks[i][j] ^ previousCipherBlock[j]);
        //         }
        //         previousCipherBlock = encryptedBlocks[i];
        //     }

        //     return result;
        // }
        
        private byte[] DecryptCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousCipherBlock = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);

                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= previousCipherBlock[j];
                }

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
                previousCipherBlock = encryptedBlock;
            }
            
            return result;
        }



        private byte[] EncryptPCBC(byte[] data)
{
    int blockSize = _blockSize;
    byte[] result = new byte[data.Length];
    byte[] previousPlaintext = (byte[])_initializationVector.Clone();
    byte[] previousCiphertext = (byte[])_initializationVector.Clone();

    for (int i = 0; i < data.Length / blockSize; i++)
    {
        int offset = i * blockSize;
        byte[] originalBlock = new byte[blockSize]; // 1. Сохраняем оригинальный блок
        Array.Copy(data, offset, originalBlock, 0, blockSize);

        byte[] blockToEncrypt = (byte[])originalBlock.Clone(); // Копируем для модификации

        for (int j = 0; j < blockSize; j++)
        {
            blockToEncrypt[j] ^= (byte)(previousPlaintext[j] ^ previousCiphertext[j]);
        }

        byte[] encryptedBlock = _algorithm.EncryptBlock(blockToEncrypt);
        Array.Copy(encryptedBlock, 0, result, offset, blockSize);

        // 2. Обновляем переменные состояния правильными значениями
        previousPlaintext = (byte[])originalBlock.Clone();
        previousCiphertext = (byte[])encryptedBlock.Clone();
    }

    return result;
}

        // private byte[] DecryptPCBC(byte[] data)
        // {
        //     int blockSize = _blockSize;
        //     byte[] result = new byte[data.Length];
        //     byte[] previousInput = (byte[])_initializationVector.Clone();
        //     byte[] previousOutput = (byte[])_initializationVector.Clone();

        //     for (int i = 0; i < data.Length / blockSize; i++)
        //     {
        //         int offset = i * blockSize;
        //         byte[] encryptedBlock = new byte[blockSize];
        //         Array.Copy(data, offset, encryptedBlock, 0, blockSize);

        //         byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);

        //         for (int j = 0; j < blockSize; j++)
        //         {
        //             decryptedBlock[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);
        //         }

        //         Array.Copy(decryptedBlock, 0, result, offset, blockSize);

        //         previousInput = (byte[])decryptedBlock.Clone();
        //         previousOutput = (byte[])encryptedBlock.Clone();
        //     }

        //     return result;
        // }

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

        // XOR с комбинацией previousInput и previousOutput
        for (int j = 0; j < blockSize; j++)
        {
            decryptedBlock[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);
        }

        Array.Copy(decryptedBlock, 0, result, offset, blockSize);

        // Исправление: previousInput = исходный открытый текст
        byte[] plainBlock = new byte[blockSize];
        for (int j = 0; j < blockSize; j++)
        {
            plainBlock[j] = (byte)(encryptedBlock[j] ^ (byte)(previousInput[j] ^ previousOutput[j]));
        }

        previousInput = (byte[])decryptedBlock.Clone(); // Используем расшифрованный блок
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

        // private byte[] EncryptOFB(byte[] data)
        // {
        //     int blockSize = _blockSize;
        //     int blockCount = data.Length / blockSize;
        //     byte[] result = new byte[data.Length];

        //     byte[] iv = (byte[])_initializationVector.Clone();
        //     byte[][] keystreamBlocks = new byte[blockCount][];

        //     var options = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };
        //     var lockObj = new object();


        //     Parallel.For(0, blockCount, options, i =>
        //     {
        //         // Console.WriteLine($"Поток {Thread.CurrentThread.ManagedThreadId}: блок {i}, {i+1} Encrypt");
        //         byte[] tempIv = (byte[])iv.Clone();

        //         for (int j = 0; j < i; j++)
        //         {
        //             lock (lockObj)
        //             {
        //                 tempIv = _algorithm.EncryptBlock(tempIv);
        //             }
        //         }
        //         lock (lockObj)
        //         {
        //             keystreamBlocks[i] = _algorithm.EncryptBlock(tempIv);
        //         }
        //     });


        //     Parallel.For(0, blockCount, options, i =>
        //     {
        //         int offset = i * blockSize;
        //         for (int j = 0; j < blockSize; j++)
        //         {
        //             result[offset + j] = (byte)(data[offset + j] ^ keystreamBlocks[i][j]);
        //         }
        //     });

        //     return result;
        // }
        
        private byte[] EncryptOFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = (byte[])_initializationVector.Clone();

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                byte[] keystream = _algorithm.EncryptBlock(feedback);
                
                // Для OFB обратная связь не зависит от данных
                feedback = keystream;

                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(block[j] ^ keystream[j]);
                }
            }
            
            return result;
        }

        private byte[] DecryptOFB(byte[] data)
        {
            return EncryptOFB(data);
        }

        // private byte[] EncryptCTR(byte[] data)
        // {
        //     int blockSize = _blockSize;
        //     int blockCount = data.Length / blockSize;
        //     byte[] result = new byte[data.Length];

        //     var options = new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount };


        //     Parallel.For(0, blockCount, options, i =>
        //     {
        //         // Console.WriteLine($"Поток {Thread.CurrentThread.ManagedThreadId}: CTR блок {i}");

        //         byte[] blockCounter = (byte[])_initializationVector.Clone();
        //         if (i > 0) IncrementCounterNtimes(blockCounter, i);


        //         byte[] keystream = _algorithm.EncryptBlock(blockCounter);

        //         int offset = i * blockSize;
        //         for (int j = 0; j < blockSize; j++)
        //         {
        //             result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
        //         }
        //     });

        //     return result;
        // }
        
       private byte[] EncryptCTR(byte[] data)
        {
            int blockSize = _blockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];

            Parallel.For(0, blockCount, i =>
            {
                // 1. Создаем копию счетчика для этого конкретного блока
                byte[] blockCounter = (byte[])_initializationVector.Clone();

                // 2. "Перематываем" счетчик на i позиций.
                // Это быстрая операция, так как мы знаем, на сколько нужно увеличить.
                // Преобразуем последние байты в число, увеличиваем и преобразуем обратно.
                // Это намного быстрее, чем цикл инкрементов.
                long counterValue = BitConverter.ToInt64(blockCounter, blockCounter.Length - 8);
                counterValue += (long)i;
                byte[] incrementedBytes = BitConverter.GetBytes(counterValue);
                Array.Copy(incrementedBytes, 0, blockCounter, blockCounter.Length - 8, 8);

                // 3. Шифруем счетчик для получения гаммы (keystream)
                byte[] keystream;
                lock (_algorithmLock)
                {
                    keystream = _algorithm.EncryptBlock(blockCounter);
                }

                // 4. Применяем XOR к данным
                int offset = i * blockSize;
                for (int j = 0; j < blockSize; j++)
                {
                    // Убедимся, что не выходим за пределы исходных данных (важно для последнего блока)
                    if (offset + j < data.Length)
                    {
                        result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                    }
                }
            });

            return result;
        }

        private void IncrementCounterNtimes(byte[] counter, int times)
        {
            for (int t = 0; t < times; t++)
                IncrementCounter(counter);
        }

        private byte[] DecryptCTR(byte[] data)
        {
            return EncryptCTR(data);
        }

       private byte[] EncryptRandomDelta(byte[] data)
        {
            int blockSize = _blockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];
            
            Parallel.For(0, blockCount, i =>
            {
                // Console.WriteLine($"Поток {Thread.CurrentThread.ManagedThreadId}: RD  блок {i}");
                byte[] delta = ComputeDeltaForBlock(_initializationVector, i);
                
                byte[] block = new byte[blockSize];
                Array.Copy(data, i * blockSize, block, 0, blockSize);
                
                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= delta[j];
                }
                
                byte[] encryptedBlock;
                lock (_algorithmLock)
                {
                    encryptedBlock = _algorithm.EncryptBlock(block);
                }
                Array.Copy(encryptedBlock, 0, result, i * blockSize, blockSize);
            });
            
            return result;
        }

        private byte[] ComputeDeltaForBlock(byte[] initialDelta, int blockIndex)
        {
            byte[] delta = (byte[])initialDelta.Clone();
            int seed = BitConverter.ToInt32(initialDelta, 0) ^ blockIndex; // Фиксированный seed
            Random random = new Random(seed);
            random.NextBytes(delta);
            return delta;
        }

        private byte[] DecryptRandomDelta(byte[] data)
        {
            int blockSize = _blockSize;
            int blockCount = data.Length / blockSize;
            byte[] result = new byte[data.Length];
            
            Parallel.For(0, blockCount, i =>
            {

                // Console.WriteLine($"Поток {Thread.CurrentThread.ManagedThreadId}: RD  блок {i}");
                byte[] delta = ComputeDeltaForBlock(_initializationVector, i);
                
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, i * blockSize, encryptedBlock, 0, blockSize);
                
                byte[] decryptedBlock;
                lock (_algorithmLock)
                {
                    decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);
                }
                
                // XOR с delta
                for (int j = 0; j < blockSize; j++)
                {
                    result[i * blockSize + j] = (byte)(decryptedBlock[j] ^ delta[j]);
                }
            });
            
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
    // Теперь, если data.Length % blockSize == 0, paddingLength будет равен blockSize.
    // Это гарантирует, что мы всегда добавляем дополнение.

    // Ваш существующий switch-блок остается здесь
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
            
            // Убираем проверку на 0 - в PKCS7 padding value не может быть 0
            if (paddingValue > data.Length) return data;
            
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
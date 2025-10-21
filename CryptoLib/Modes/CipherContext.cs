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

        private (byte[] Plaintext, byte[] Ciphertext) _pcbcFeedbackRegisters;

        private byte[] _feedbackRegister = default!;

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
        
        private void InitializeState()
        {
            if (_mode != CipherMode.ECB && _initializationVector != null)
            {
                _feedbackRegister = (byte[])_initializationVector.Clone();
                _pcbcFeedbackRegisters = 
                (
                    (byte[])_initializationVector.Clone(), 
                    (byte[])_initializationVector.Clone()
                );
            }
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
            InitializeState(); 
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
            InitializeState(); 
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

        // Ебанем весь файл в оперативку? ГО
        // public async Task EncryptAsync(string inputFilePath, string outputFilePath)
        // {
        //     if (!File.Exists(inputFilePath))
        //         throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

        //     byte[] inputData = await File.ReadAllBytesAsync(inputFilePath);
        //     byte[] encryptedData = await EncryptDataAsync(inputData);
        //     await File.WriteAllBytesAsync(outputFilePath, encryptedData);
        // }

        // public async Task DecryptAsync(string inputFilePath, string outputFilePath)
        // {
        //     if (!File.Exists(inputFilePath))
        //         throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

        //     byte[] inputData = await File.ReadAllBytesAsync(inputFilePath);
        //     byte[] decryptedData = await DecryptDataAsync(inputData);
        //     await File.WriteAllBytesAsync(outputFilePath, decryptedData);
        // }

        public async Task EncryptAsync(string inputFilePath, string outputFilePath)
        {
            InitializeState(); 
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            await using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            await EncryptAsync(inputFileStream, outputFileStream);
        }

        public async Task DecryptAsync(string inputFilePath, string outputFilePath)
        {
            InitializeState(); 
            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException($"Входной файл не найден: {inputFilePath}");

            await using var inputFileStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
            await using var outputFileStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);
            await DecryptAsync(inputFileStream, outputFileStream); // Делегируем потоковой версии
        }

        // НОВЫЕ ОСНОВНЫЕ МЕТОДЫ
        public async Task EncryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();
            const int bufferSize = 65536; 
            byte[] buffer = new byte[bufferSize];
            int bytesRead;

            while ((bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                // Проверяем, является ли этот чанк последним.
                // Самый надежный способ - если мы прочитали меньше данных, чем размер буфера.
                bool isLastChunk = bytesRead < bufferSize;

                byte[] chunkToEncrypt;
                if (isLastChunk)
                {
                    // Если чанк последний, мы должны его обрезать до реального размера и применить паддинг.
                    byte[] finalData = new byte[bytesRead];
                    Array.Copy(buffer, finalData, bytesRead);
                    chunkToEncrypt = ApplyPadding(finalData, _blockSize);
                }
                else
                {
                    // Если чанк не последний, он должен быть полным. Шифруем его как есть.
                    // Никакого паддинга здесь не нужно.
                    chunkToEncrypt = buffer;
                }
                
                byte[] encryptedChunk = EncryptData(chunkToEncrypt);
                
                await outputStream.WriteAsync(encryptedChunk, 0, encryptedChunk.Length);
            }
        }

        public async Task DecryptAsync(Stream inputStream, Stream outputStream)
        {
            InitializeState();
            const int bufferSize = 65536;
            byte[] buffer = new byte[bufferSize];
            int bytesRead;
            
            // Создаем буфер для хранения предыдущего прочитанного блока.
            // Мы выделяем память ОДИН РАЗ, а не в цикле!
            byte[] previousChunk = new byte[bufferSize];
            int previousBytesRead = 0;

            // 1. Читаем самый первый блок в `previousChunk`
            previousBytesRead = await inputStream.ReadAsync(previousChunk, 0, previousChunk.Length);

            while (previousBytesRead > 0)
            {
                // 2. Читаем следующий блок в основной `buffer`
                bytesRead = await inputStream.ReadAsync(buffer, 0, buffer.Length);

                // 3. Проверяем, был ли предыдущий блок последним
                if (bytesRead == 0)
                {
                    // Да, `previousChunk` - это последний блок.
                    // Обрезаем его до реального размера.
                    byte[] finalChunk = new byte[previousBytesRead];
                    Array.Copy(previousChunk, finalChunk, previousBytesRead);

                    // Расшифровываем и удаляем паддинг
                    byte[] decryptedFinal = DecryptData(finalChunk);
                    byte[] unpaddedFinal = RemovePadding(decryptedFinal);
                    await outputStream.WriteAsync(unpaddedFinal, 0, unpaddedFinal.Length);
                }
                else
                {
                    // Нет, `previousChunk` - это промежуточный блок.
                    // Просто расшифровываем и записываем его.
                    byte[] decryptedPrevious = DecryptData(previousChunk);
                    await outputStream.WriteAsync(decryptedPrevious, 0, decryptedPrevious.Length);
                }

                // 4. Текущий блок становится предыдущим для следующей итерации.
                // Мы не создаем новую память, а просто копируем данные и количество байт.
                Array.Copy(buffer, previousChunk, bytesRead);
                previousBytesRead = bytesRead;
            }
        }

        // эта хуйня вроде не  используется
        // private async Task<byte[]> EncryptDataAsync(byte[] data)
        // {
        //     return await Task.Run(() =>
        //     {
        //         byte[] paddedData = ApplyPadding(data, _blockSize);
        //         return EncryptData(paddedData);
        //     });
        // }

        // private async Task<byte[]> DecryptDataAsync(byte[] data)
        // {
        //     return await Task.Run(() =>
        //     {
        //         byte[] decryptedData = DecryptData(data);
        //         return RemovePadding(decryptedData);
        //     });
        // }

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
                
                // БЛОКИРОВКА УБРАНА - теперь это безопасно и быстро
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
                
                // Блокировка убрана
                byte[] decryptedBlock = _algorithm.DecryptBlock(block);

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
            });
            
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

        private byte[] EncryptCBC(byte[] data)
        {            
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = _feedbackRegister; 
            
            // Создаем рабочий буфер ОДИН РАЗ
            byte[] block = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                // Переиспользуем рабочий буфер
                Array.Copy(data, offset, block, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= previousBlock[j];
                }

                byte[] encryptedBlock = _algorithm.EncryptBlock(block);
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
                
                // Обновляем состояние для следующего блока.
                // encryptedBlock - это новый массив, возвращенный из EncryptBlock,
                // поэтому здесь простое присваивание безопасно.
                previousBlock = encryptedBlock;
            }
            
            _feedbackRegister = previousBlock; 
            return result;
        }

        private byte[] DecryptCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] previousBlock = _feedbackRegister; 

            // Создаем рабочий буфер ОДИН РАЗ
            byte[] encryptedBlock = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                // Переиспользуем рабочий буфер
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);

                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= previousBlock[j];
                }

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
                
                // ПРАВИЛЬНОЕ ОБНОВЛЕНИЕ СОСТОЯНИЯ
                // Мы должны сохранить копию текущего шифроблока,
                // прежде чем буфер encryptedBlock будет перезаписан на следующей итерации.
                previousBlock = (byte[])encryptedBlock.Clone();
            }
            _feedbackRegister = previousBlock; 

            return result;
        }



        private byte[] EncryptPCBC(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            var (previousInput, previousOutput) = _pcbcFeedbackRegisters;

            // Создаем буферы ОДИН РАЗ перед циклом
            byte[] originalBlock = new byte[blockSize];
            byte[] blockToEncrypt = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                // Переиспользуем буферы, не создавая новые
                Array.Copy(data, offset, originalBlock, 0, blockSize);
                Array.Copy(originalBlock, 0, blockToEncrypt, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    blockToEncrypt[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);
                }
                
                byte[] encryptedBlock;
                lock(_algorithmLock)
                {
                    encryptedBlock = _algorithm.EncryptBlock(blockToEncrypt);
                }
                Array.Copy(encryptedBlock, 0, result, offset, blockSize);

                previousInput = (byte[])originalBlock.Clone();
                previousOutput = (byte[])encryptedBlock.Clone();
            }
            
            _pcbcFeedbackRegisters = (previousInput, previousOutput);
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
            var (previousInput, previousOutput) = _pcbcFeedbackRegisters;

            // Создаем буфер ОДИН РАЗ перед циклом
            byte[] encryptedBlock = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                // Переиспользуем буфер
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);
                
                byte[] decryptedBlock;
                lock(_algorithmLock)
                {
                    decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);
                }

                for (int j = 0; j < blockSize; j++)
                {
                    decryptedBlock[j] ^= (byte)(previousInput[j] ^ previousOutput[j]);
                }

                Array.Copy(decryptedBlock, 0, result, offset, blockSize);
                
                previousInput = (byte[])decryptedBlock.Clone();
                previousOutput = (byte[])encryptedBlock.Clone();
            }
            
            _pcbcFeedbackRegisters = (previousInput, previousOutput);
            return result;
        }

        private byte[] EncryptCFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = _feedbackRegister;

            // Создаем буфер ОДИН РАЗ перед циклом
            byte[] block = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                
                byte[] encryptedFeedback;
                lock(_algorithmLock)
                {
                    encryptedFeedback = _algorithm.EncryptBlock(feedback);
                }

                // Переиспользуем буфер
                Array.Copy(data, offset, block, 0, blockSize);
                
                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(block[j] ^ encryptedFeedback[j]);
                }
                
                Array.Copy(result, offset, feedback, 0, blockSize);
            }
            
            _feedbackRegister = feedback;
            return result;
        }

        private byte[] DecryptCFB(byte[] data)
        {
            int blockSize = _blockSize;
            byte[] result = new byte[data.Length];
            byte[] feedback = _feedbackRegister;

            // Создаем буфер ОДИН РАЗ перед циклом
            byte[] encryptedBlock = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                
                byte[] encryptedFeedback;
                lock(_algorithmLock)
                {
                    encryptedFeedback = _algorithm.EncryptBlock(feedback);
                }
                
                // Переиспользуем буфер
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);

                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(encryptedBlock[j] ^ encryptedFeedback[j]);
                }
                
                Array.Copy(encryptedBlock, 0, feedback, 0, blockSize);
            }
            
            _feedbackRegister = feedback;
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
            byte[] feedback = _feedbackRegister;

            // Создаем буфер ОДИН РАЗ перед циклом
            byte[] block = new byte[blockSize];

            for (int i = 0; i < data.Length / blockSize; i++)
            {
                int offset = i * blockSize;
                
                byte[] keystream;
                lock (_algorithmLock)
                {
                    keystream = _algorithm.EncryptBlock(feedback);
                }
                
                feedback = keystream;

                // Переиспользуем буфер
                Array.Copy(data, offset, block, 0, blockSize);
                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(block[j] ^ keystream[j]);
                }
            }
            
            _feedbackRegister = feedback;
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

            Parallel.For(0, blockCount,
                // localInit: Создаем пару буферов ОДИН РАЗ для КАЖДОГО потока.
                // Item1: буфер для blockCounter. Item2: буфер для байтов инкремента.
                () => (new byte[blockSize], new byte[8]),
                
                // body: Основная логика, использующая thread-local буферы.
                (i, loopState, localBuffers) =>
                {
                    var (blockCounter, incrementedBytes) = localBuffers;

                    // Копируем исходный IV в наш локальный буфер, НЕ создавая новый массив.
                    Array.Copy(_initializationVector, blockCounter, blockSize);

                    long counterValue = BitConverter.ToInt64(blockCounter, blockCounter.Length - 8);
                    counterValue += (long)i;

                    // Используем второй буфер, НЕ создавая новый массив.
                    BitConverter.TryWriteBytes(incrementedBytes, counterValue);
                    Array.Copy(incrementedBytes, 0, blockCounter, blockCounter.Length - 8, 8);

                    byte[] keystream = _algorithm.EncryptBlock(blockCounter);

                    int offset = i * blockSize;
                    for (int j = 0; j < blockSize; j++)
                    {
                        if (offset + j < data.Length)
                        {
                            result[offset + j] = (byte)(data[offset + j] ^ keystream[j]);
                        }
                    }
                    
                    // Возвращаем буферы для следующей итерации этого же потока.
                    return localBuffers;
                },
                
                // localFinally: Ничего не делаем при завершении потока.
                _ => { });

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
                int offset = i * blockSize;
                byte[] delta = ComputeDeltaForBlock(_initializationVector, i);
                
                byte[] block = new byte[blockSize];
                Array.Copy(data, offset, block, 0, blockSize);
                
                for (int j = 0; j < blockSize; j++)
                {
                    block[j] ^= delta[j];
                }
                
                // Блокировка убрана
                byte[] encryptedBlock = _algorithm.EncryptBlock(block);

                Array.Copy(encryptedBlock, 0, result, offset, blockSize);
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
                int offset = i * blockSize;
                byte[] delta = ComputeDeltaForBlock(_initializationVector, i);
                
                byte[] encryptedBlock = new byte[blockSize];
                Array.Copy(data, offset, encryptedBlock, 0, blockSize);
                
                // Блокировка убрана
                byte[] decryptedBlock = _algorithm.DecryptBlock(encryptedBlock);
                
                for (int j = 0; j < blockSize; j++)
                {
                    result[offset + j] = (byte)(decryptedBlock[j] ^ delta[j]);
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
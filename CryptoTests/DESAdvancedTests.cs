using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.Interfaces; // Убедись, что твои интерфейсы и классы здесь доступны
using CryptoLib.Modes;      // Убедись, что твои интерфейсы и классы здесь доступны
using Xunit;

namespace CryptoTests
{
    public class DES_AdvancedTests
    {
        private readonly byte[] _testKey = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
        private readonly byte[] _testIV = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        /// <summary>
        /// Генератор данных для теста. Создает все возможные комбинации
        /// из тестовых файлов и режимов шифрования.
        /// </summary>
        public static IEnumerable<object[]> TestDataGenerator()
        {
            // 1. Список путей к файлам
            string[] filePaths = 
            [
                // "TestData/text.txt",
                "TestData/image.jpg",
                // "TestData/audio.mp3",
                // "TestData/video.mp4",
                // "TestData/archive.zip"
            ];

            // 2. Список всех режимов шифрования
            var cipherModes = Enum.GetValues<CipherMode>();

            // 3. Создаем декартово произведение: (файл1, режим1), (файл1, режим2), ...
            foreach (var filePath in filePaths)
            {
                foreach (var mode in cipherModes)
                {
                    yield return new object[] { filePath, mode };
                }
            }
        }

        /// <summary>
        /// Комплексный параметризованный тест для всех файлов и режимов шифрования.
        /// Что проверяет: корректность шифрования/дешифрования для каждой комбинации файла и режима.
        /// 
        /// Ожидаемое поведение: каждый тест должен завершиться успешно,
        /// а расшифрованные данные - полностью совпадать с исходными.
        /// 
        /// ВАЖНО: Если этот тест ПАДАЕТ, вывод укажет на КОНКРЕТНЫЙ режим шифрования,
        /// который работает неправильно.
        /// 
        /// ВАЖНО: Если этот тест ЗАВИСАЕТ, это с вероятностью 99% означает, что
        /// в вашей реализации EncryptAsync/DecryptAsync не закрываются файловые потоки
        /// (FileStream) при возникновении ошибки. Оберните их в `await using`.
        /// </summary>
        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task ComprehensiveFileEncryptDecrypt_ShouldSucceed(string inputFilePath, CipherMode mode)
        {
            // Arrange
            Assert.True(File.Exists(inputFilePath), $"Тестовый файл не найден: {inputFilePath}");

            // Режим ECB не использует вектор инициализации (IV)
            byte[] iv = mode == CipherMode.ECB ? null : _testIV;
            
            // Мы используем PKCS7 как наиболее стандартный режим дополнения
            // Если нужно, можно и его сделать параметром теста
            var context = new CipherContext(_testKey, mode, PaddingMode.PKCS7, iv);

            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                // Act
                await context.EncryptAsync(inputFilePath, encryptedFile);
                await context.DecryptAsync(encryptedFile, decryptedFile);

                // Assert
                // Сравниваем файлы побайтово для 100% уверенности
                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);

                // xUnit предоставит детальный вывод, если байты не совпадут
                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                // Гарантированная очистка временных файлов
                // Этот блок выполнится даже после падения Assert
                File.Delete(encryptedFile);
                File.Delete(decryptedFile);
            }
        }
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.Interfaces;
using CryptoLib.Modes;
using Xunit;
using Xunit.Abstractions; // <--- ДОБАВЬТЕ ЭТОТ using

namespace CryptoTests
{
    public class DES_AdvancedTests
    {
        private readonly byte[] _testKey = { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
        private readonly byte[] _testIV = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };

        // --- ДОБАВЬТЕ ЭТИ ДВЕ ЧАСТИ ДЛЯ ВЫВОДА ДИАГНОСТИКИ ---
        private readonly ITestOutputHelper _testOutputHelper;

        public DES_AdvancedTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }
        // ----------------------------------------------------

        public static IEnumerable<object[]> TestDataGenerator()
        {
            // Раскомментируйте все файлы, чтобы получить полные данные
            string[] filePaths = 
            {
                "TestData/text.txt",
                "TestData/image.jpg",
                // "TestData/audio.mp3",
                // "TestData/video.mp4",
                // "TestData/archive.zip"
            };

            var cipherModes = Enum.GetValues<CipherMode>();

            foreach (var filePath in filePaths)
            {
                foreach (var mode in cipherModes)
                {
                    yield return new object[] { filePath, mode };
                }
            }
        }

        [Theory]
        [MemberData(nameof(TestDataGenerator))]
        public async Task ComprehensiveFileEncryptDecrypt_ShouldSucceed(string inputFilePath, CipherMode mode)
        {
            // --- НАЧАЛО ДИАГНОСТИКИ ---
            var diagnostics = new System.Text.StringBuilder();
            diagnostics.AppendLine($"\n--- DIAGNOSTICS for {Path.GetFileName(inputFilePath)} [{new FileInfo(inputFilePath).Length / 1024.0:F2} KB] with {mode} ---");
            var totalStopwatch = System.Diagnostics.Stopwatch.StartNew();
            // --- КОНЕЦ ДИАГНОСТИКИ ---

            // Arrange
            Assert.True(File.Exists(inputFilePath), $"Тестовый файл не найден: {inputFilePath}");

            byte[] iv = mode == CipherMode.ECB ? null : _testIV;
            var context = new CipherContext(_testKey, mode, PaddingMode.PKCS7, iv);

            string encryptedFile = Path.GetTempFileName();
            string decryptedFile = Path.GetTempFileName();

            try
            {
                // Act
                var encryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                await context.EncryptAsync(inputFilePath, encryptedFile);
                encryptStopwatch.Stop();
                diagnostics.AppendLine($"  Encryption took: {encryptStopwatch.ElapsedMilliseconds,7} ms");

                var decryptStopwatch = System.Diagnostics.Stopwatch.StartNew();
                await context.DecryptAsync(encryptedFile, decryptedFile);
                decryptStopwatch.Stop();
                diagnostics.AppendLine($"  Decryption took: {decryptStopwatch.ElapsedMilliseconds,7} ms");

                // Assert
                var verificationStopwatch = System.Diagnostics.Stopwatch.StartNew();
                byte[] originalBytes = await File.ReadAllBytesAsync(inputFilePath);
                byte[] decryptedBytes = await File.ReadAllBytesAsync(decryptedFile);
                verificationStopwatch.Stop();
                diagnostics.AppendLine($"  Verification took: {verificationStopwatch.ElapsedMilliseconds,7} ms");
                
                Assert.Equal(originalBytes, decryptedBytes);
            }
            finally
            {
                File.Delete(encryptedFile);
                File.Delete(decryptedFile);
                totalStopwatch.Stop();
                diagnostics.AppendLine($"  Total test time: {totalStopwatch.ElapsedMilliseconds,7} ms");
                
                // Выводим всю собранную информацию в лог теста
                _testOutputHelper.WriteLine(diagnostics.ToString());
            }
        }
    }
}
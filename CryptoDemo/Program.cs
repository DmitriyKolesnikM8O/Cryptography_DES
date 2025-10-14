using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using CryptoLib.Algorithms.DES;
using CryptoLib.Algorithms.DEAL;
using CryptoLib.Modes;

namespace CryptoDemo
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("=== CryptoLab DEMO - DES/DEAL Algorithms ===");
            
            while (true)
            {
                Console.WriteLine("\nВыберите действие:");
                Console.WriteLine("1. Демонстрация DES");
                Console.WriteLine("2. Демонстрация DEAL");
                Console.WriteLine("3. Шифрование файла");
                Console.WriteLine("4. Дешифрование файла");
                Console.WriteLine("0. Выход");
                
                var choice = Console.ReadLine();
                
                switch (choice)
                {
                    case "1":
                        await DemonstrateDES();
                        break;
                    case "2":
                        await DemonstrateDEAL();
                        break;
                    case "3":
                        await EncryptFile();
                        break;
                    case "4":
                        await DecryptFile();
                        break;
                    case "0":
                        return;
                    default:
                        Console.WriteLine("Неверный выбор");
                        break;
                }
            }
        }
        
        static async Task DemonstrateDES()
        {
            Console.WriteLine("\n=== Демонстрация DES ===");
            
            byte[] key = new byte[8] { 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
            byte[] iv = new byte[8] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
            byte[] testData = new byte[16] { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 
            };
            
            Console.WriteLine("Ключ: " + BitConverter.ToString(key));
            Console.WriteLine("Данные: " + BitConverter.ToString(testData));
            
            // Тестируем все режимы
            var modes = new[] { 
                CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, 
                CipherMode.CFB, CipherMode.OFB, CipherMode.CTR 
            };
            
            foreach (var mode in modes)
            {
                Console.WriteLine($"\n--- Режим {mode} ---");
                
                try
                {
                    byte[] ivForMode = mode == CipherMode.ECB ? null : iv;
                    var context = new CipherContext(key, mode, PaddingMode.PKCS7, ivForMode,
                        new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "DES"));
                    
                    byte[] encrypted = new byte[32];
                    await context.EncryptAsync(testData, encrypted);
                    
                    byte[] decrypted = new byte[32];
                    await context.DecryptAsync(encrypted, decrypted);
                    
                    bool success = testData.SequenceEqual(decrypted.Take(testData.Length));
                    Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}");
                    Console.WriteLine($"Зашифровано: {BitConverter.ToString(encrypted.Take(16).ToArray())}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка: {ex.Message}");
                }
            }
        }
        
        static async Task DemonstrateDEAL()
        {
            Console.WriteLine("\n=== Демонстрация DEAL ===");
            
            byte[] key128 = new byte[16] { 
                0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1,
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
            };
            
            byte[] iv = new byte[16] { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
            };
            
            byte[] testData = new byte[16] { 
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 
            };
            
            Console.WriteLine("Ключ (128-bit): " + BitConverter.ToString(key128));
            Console.WriteLine("Данные: " + BitConverter.ToString(testData));
            
            // Тестируем все режимы для DEAL-128
            var modes = new[] { 
                CipherMode.ECB, CipherMode.CBC, CipherMode.PCBC, 
                CipherMode.CFB, CipherMode.OFB, CipherMode.CTR 
            };
            
            foreach (var mode in modes)
            {
                Console.WriteLine($"\n--- DEAL-128 Режим {mode} ---");
                
                try
                {
                    byte[] ivForMode = mode == CipherMode.ECB ? null : iv;
                    var context = new CipherContext(key128, mode, PaddingMode.PKCS7, ivForMode,
                        new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", "DEAL"));
                    
                    byte[] encrypted = new byte[32];
                    await context.EncryptAsync(testData, encrypted);
                    
                    byte[] decrypted = new byte[32];
                    await context.DecryptAsync(encrypted, decrypted);
                    
                    bool success = testData.SequenceEqual(decrypted.Take(testData.Length));
                    Console.WriteLine($"Результат: {(success ? "УСПЕХ" : "ОШИБКА")}");
                    Console.WriteLine($"Зашифровано: {BitConverter.ToString(encrypted.Take(16).ToArray())}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Ошибка: {ex.Message}");
                }
            }
        }
        
        static async Task EncryptFile()
        {
            Console.WriteLine("\n=== Шифрование файла ===");
            
            Console.Write("Введите путь к исходному файлу: ");
            string inputFile = Console.ReadLine();
            
            Console.Write("Введите путь для зашифрованного файла: ");
            string outputFile = Console.ReadLine();
            
            Console.WriteLine("Выберите алгоритм:");
            Console.WriteLine("1. DES (64-bit ключ)");
            Console.WriteLine("2. DEAL-128 (128-bit ключ)");
            Console.WriteLine("3. DEAL-192 (192-bit ключ)");
            Console.WriteLine("4. DEAL-256 (256-bit ключ)");
            string algoChoice = Console.ReadLine();
            
            Console.WriteLine("Выберите режим шифрования:");
            var modes = Enum.GetValues(typeof(CipherMode)).Cast<CipherMode>();
            int i = 1;
            foreach (var mode in modes)
            {
                Console.WriteLine($"{i}. {mode}");
                i++;
            }
            string modeChoice = Console.ReadLine();
            
            if (!File.Exists(inputFile))
            {
                Console.WriteLine("Исходный файл не существует!");
                return;
            }
            
            try
            {
                byte[] key = GenerateKey(algoChoice);
                CipherMode mode = modes.ElementAt(int.Parse(modeChoice) - 1);
                byte[] iv = GenerateIV(algoChoice);
                var padding = (mode == CipherMode.CFB || mode == CipherMode.OFB || mode == CipherMode.CTR) 
                    ? PaddingMode.Zeros : PaddingMode.PKCS7;

                var context = new CipherContext(key, mode, padding, iv,
                    new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", 
                        algoChoice == "1" ? "DES" : "DEAL"));
                
                await context.EncryptAsync(inputFile, outputFile);
                Console.WriteLine($"Файл успешно зашифрован: {outputFile}");
                Console.WriteLine($"Использован ключ: {BitConverter.ToString(key)}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при шифровании: {ex.Message}");
            }
        }
        
        static async Task DecryptFile()
        {
            Console.WriteLine("\n=== Дешифрование файла ===");
            
            Console.Write("Введите путь к зашифрованному файлу: ");
            string inputFile = Console.ReadLine();
            
            Console.Write("Введите путь для расшифрованного файла: ");
            string outputFile = Console.ReadLine();
            
            Console.Write("Введите ключ (hex строка): ");
            string keyHex = Console.ReadLine();
            
            Console.Write("Введите алгоритм (DES/DEAL): ");
            string algorithm = Console.ReadLine();
            
            Console.Write("Введите режим шифрования: ");
            string modeStr = Console.ReadLine();
            
            if (!File.Exists(inputFile))
            {
                Console.WriteLine("Зашифрованный файл не существует!");
                return;
            }
            
            try
            {
                byte[] key = HexStringToByteArray(keyHex);
                CipherMode mode = (CipherMode)Enum.Parse(typeof(CipherMode), modeStr);
                byte[] iv = GenerateIV(algorithm == "DES" ? "1" : "2");
                
                var padding = (mode == CipherMode.CFB || mode == CipherMode.OFB || mode == CipherMode.CTR) 
                    ? PaddingMode.Zeros : PaddingMode.PKCS7;
                var context = new CipherContext(key, mode, padding, iv,
                    new System.Collections.Generic.KeyValuePair<string, object>("Algorithm", algorithm));
                
                await context.DecryptAsync(inputFile, outputFile);
                Console.WriteLine($"Файл успешно расшифрован: {outputFile}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при дешифровании: {ex.Message}");
            }
        }
        
        static byte[] GenerateKey(string choice)
        {
            Random rnd = new Random();
            return choice switch
            {
                "1" => Enumerable.Range(0, 8).Select(_ => (byte)rnd.Next(256)).ToArray(),  // DES
                "2" => Enumerable.Range(0, 16).Select(_ => (byte)rnd.Next(256)).ToArray(), // DEAL-128
                "3" => Enumerable.Range(0, 24).Select(_ => (byte)rnd.Next(256)).ToArray(), // DEAL-192
                "4" => Enumerable.Range(0, 32).Select(_ => (byte)rnd.Next(256)).ToArray(), // DEAL-256
                _ => throw new ArgumentException("Неверный выбор алгоритма")
            };
        }
        
        static byte[] GenerateIV(string algoChoice)
        {
            Random rnd = new Random();
            int size = algoChoice == "1" ? 8 : 16; // DES=8, DEAL=16
            return Enumerable.Range(0, size).Select(_ => (byte)rnd.Next(256)).ToArray();
        }
        
        static byte[] HexStringToByteArray(string hex)
        {
            
            hex = hex.Replace("-", "").Replace(" ", "").Replace(":", "");
            
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have even length");
            
            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return result;
        }
    }
}
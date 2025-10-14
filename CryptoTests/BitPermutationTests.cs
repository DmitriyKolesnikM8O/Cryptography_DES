using Xunit;
using CryptoLib.Core;
using System;
using System.Linq;


/*
1. LSB + нумерация 0
2. LSB + нумерация 1
3. MSB + нумерация 0
4. MSB + нумерация 1
5. Невалидный P-блок
6.Один бит
7.Пустой P-блок 
8.Полная перестановка
*/


namespace CryptoTests
{
    public class BitPermutationTests
    {
        private readonly byte[] Input64Bits = new byte[] { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
        private readonly int[] SmallPBlock = new int[] { 0, 7, 8, 15, 63 };

        /// <summary>
        /// Тестирует базовый случай LSB режима с нумерацией с 0
        /// Что проверяет: правильность извлечения и записи битов в LSB порядке
        /// Ожидаемое поведение: биты 0,7,8,15,63 извлекаются как 0,1,0,1,0 
        /// и записываются в младшие биты байта = 00001010b = 0x0A
        /// </summary>
        [Fact]
        public void PermuteBits_LsbToMsb_IndexFromZero_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = true;
            bool startIndexZero = true;


            byte[] expected = "\n"u8.ToArray();

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, SmallPBlock, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует LSB режим с нумерацией с 1 (как в некоторых стандартах)
        /// Что проверяет: корректность работы смещения индексов при нумерации с 1
        /// Ожидаемое поведение: P-блок {1,8,9,16,64} должен дать тот же результат,
        /// что и {0,7,8,15,63} при нумерации с 0
        /// </summary>
        [Fact]
        public void PermuteBits_LsbToMsb_IndexFromOne_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = true;
            bool startIndexZero = false;

            int[] pBlockFromOne = SmallPBlock.Select(i => i + 1).ToArray();
            byte[] expected = "\n"u8.ToArray();

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, pBlockFromOne, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует базовый случай MSB режима с нумерацией с 0 (стандарт для многих алгоритмов)
        /// Что проверяет: правильность извлечения и записи битов в MSB порядке
        /// Ожидаемое поведение: биты 0,7,8,15,63 извлекаются как 1,0,1,0,0
        /// и записываются в старшие биты байта = 10100000b = 0xA0
        /// </summary>
        [Fact]
        public void PermuteBits_MsbToLsb_IndexFromZero_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = false;
            bool startIndexZero = true;


            byte[] expected = [0xA0];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, SmallPBlock, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует MSB режим с нумерацией с 1 (как в DES)
        /// Что проверяет: корректность работы MSB режима с нумерацией с 1
        /// Ожидаемое поведение: P-блок {1,8,9,16,64} должен дать тот же результат,
        /// что и {0,7,8,15,63} при нумерации с 0 в MSB режиме
        /// </summary>
        [Fact]
        public void PermuteBits_MsbToLsb_IndexFromOne_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = false;
            bool startIndexZero = false;

            int[] pBlockFromOne = SmallPBlock.Select(i => i + 1).ToArray();
            byte[] expected = [0xA0];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, pBlockFromOne, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует обработку ошибок при невалидных индексах P-блока
        /// Что проверяет: корректность валидации входных данных
        /// Ожидаемое поведение: при передаче индекса 64 (при 64-битном входе)
        /// должен выбрасываться ArgumentException
        /// </summary>
        [Fact]
        public void PermuteBits_InvalidPBlock_ThrowsException()
        {
            int[] invalidPBlock = [0, 64];
            bool indexFromLsb = true;
            bool startIndexZero = true;

            Assert.Throws<ArgumentException>(() =>
            {
                BitPermutation.PermutationBytes(Input64Bits, invalidPBlock, indexFromLsb, startIndexZero);
            });
        }

        /// <summary>
        /// Тестирует граничный случай - перестановку одного бита
        /// Что проверяет: корректность работы при минимальном количестве битов
        /// Ожидаемое поведение: извлечение бита 7 (MSB первого байта = 1)
        /// и запись его в результат = 00000001b = 0x01
        /// </summary>
        [Fact]
        public void PermuteBits_SingleBit_ShouldReturnCorrectResult()
        {
            bool indexFromLsb = true;
            bool startIndexZero = true;

            int[] singleBitPBlock = [7];


            byte[] expected = [0x01];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, singleBitPBlock, indexFromLsb, startIndexZero);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Тестирует граничный случай - пустой P-блок
        /// Что проверяет: корректность обработки нулевого количества битов
        /// Ожидаемое поведение: возвращается пустой массив байтов
        /// </summary>
        [Fact]
        public void PermuteBits_EmptyPBlock_ShouldReturnEmptyArray()
        {
            int[] emptyPBlock = [];
            byte[] expected = [];

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, emptyPBlock, true, true);
            Assert.Equal(expected, actual);
        }

        /// <summary>
        /// Дополнительный тест: проверка полной 64-битной перестановки
        /// Что проверяет: корректность работы с максимальным количеством битов
        /// Ожидаемое поведение: создается 8-байтовый результат без ошибок
        /// </summary>
        [Fact]
        public void PermuteBits_Full64BitPermutation_ShouldReturnCorrectSize()
        {
            bool indexFromLsb = false;
            bool startIndexZero = false;

            // P-блок, который просто меняет порядок байтов
            int[] fullPBlock = new int[64];
            for (int i = 0; i < 64; i++)
            {
                fullPBlock[i] = 64 - i; // Обратный порядок
            }

            byte[] actual = BitPermutation.PermutationBytes(Input64Bits, fullPBlock, indexFromLsb, startIndexZero);

            Assert.NotNull(actual);
            Assert.Equal(8, actual.Length); // 64 бита = 8 байт
        }
    }
}
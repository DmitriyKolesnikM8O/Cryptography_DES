Ожидаемая структура работы:

```text
CryptoLab_DES/
│
├── CryptoLib/                   # библиотека с реализацией DES/DEAL
│   ├── Core/
│   │   ├── BitPermutation.cs
│   │   ├── BitUtils.cs
│   ├── Interfaces/
│   │   ├── IKeyScheduler.cs
│   │   ├── IFeistelFunction.cs
│   │   ├── ISymmetricCipher.cs
│   ├── Algorithms/
│   │   ├── FeistelNetwork.cs
│   │   ├── DES/
│   │   │   ├── DESTables.cs
│   │   │   ├── DESKeyScheduler.cs
│   │   │   ├── DESFeistelFunction.cs
│   │   │   ├── DESAlgorithm.cs
│   │   ├── DEAL/
│   │       ├── DEALAlgorithm.cs
│   │       ├── DESAdapter.cs
│   ├── Modes/
│   │   ├── CipherContext.cs
│   │   ├── CipherMode.cs
│   │   ├── PaddingMode.cs
│   └── CryptoLib.csproj
│
├── CryptoDemo/                   # консольное демо для лабораторной
│   ├── Program.cs
│   └── CryptoDemo.csproj
│
├── CryptoTests/                  # модульные тесты
│   ├── BitPermutationTests.cs
│   ├── DESTests.cs
│   └── CryptoTests.csproj
│
├── CryptoLab_DES.sln
│
├── README.md
│
└── ...
````


TO-DO:
- точно ли только ECB можно распараллелить?
- для файлов мб параллельные потоки лучше
- в паддинги мб тоже параллелизм запихать
Ожидаемая структура работы:

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
│   │   │   ├── Tables.cs
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

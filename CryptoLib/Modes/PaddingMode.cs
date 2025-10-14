namespace CryptoLib.Modes
{
    /// <summary>
    /// Режимы дополнения (padding) для блочных шифров
    /// </summary>
    public enum PaddingMode
    {
        /// <summary>Дополнение нулями</summary>
        Zeros,
        
        /// <summary>Стандарт ANSI X.923</summary>
        ANSIX923,
        
        /// <summary>Стандарт PKCS#7</summary>
        PKCS7,
        
        /// <summary>Стандарт ISO 10126</summary>
        ISO10126
    }
}
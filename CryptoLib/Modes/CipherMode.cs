namespace CryptoLib.Modes
{
    /// <summary>
    /// Режимы шифрования для блочных шифров
    /// </summary>
    public enum CipherMode
    {
        /// <summary>Electronic Codebook - Простая замена блоков</summary>
        ECB,
        
        /// <summary>Cipher Block Chaining - Сцепление блоков шифротекста</summary>
        CBC,
        
        /// <summary>Propagating Cipher Block Chaining - Распространяющееся сцепление</summary>
        PCBC,
        
        /// <summary>Cipher Feedback - Обратная связь по шифротексту</summary>
        CFB,
        
        /// <summary>Output Feedback - Обратная связь по выходу</summary>
        OFB,
        
        /// <summary>Counter - Режим счетчика</summary>
        CTR,
        
        /// <summary>Random Delta - Случайная дельта</summary>
        RandomDelta
    }
}
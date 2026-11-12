using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab5_1
{
    class Program
    {
        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            string originalText = "Сьогодні гарна погода";

            Console.WriteLine($"Оригінальний текст\n{originalText}\n");

            // Алгоритм DES: ключ 8 байт, IV 8 байт
            Console.WriteLine("Алгоритм DES");
            using (DES des = DES.Create())
            {
                byte[] key = GenerateRandomBytes(8);
                byte[] iv = GenerateRandomBytes(8);

                byte[] encrypted = Encrypt(originalText, key, iv, des);
                string decrypted = Decrypt(encrypted, key, iv, des);

                PrintResult(key, iv, encrypted, decrypted);
            }

            // Алгоритм Triple-DES: ключ 24 байти, IV 8 байт
            Console.WriteLine("Алгоритм Triple-DES");
            using (TripleDES tdes = TripleDES.Create())
            {
                byte[] key = GenerateRandomBytes(24);
                byte[] iv = GenerateRandomBytes(8);

                byte[] encrypted = Encrypt(originalText, key, iv, tdes);
                string decrypted = Decrypt(encrypted, key, iv, tdes);

                PrintResult(key, iv, encrypted, decrypted);
            }

            // Алгоритм AES: ключ 32 байти, IV 16 байт
            Console.WriteLine("Алгоритм AES");
            using (Aes aes = Aes.Create())
            {
                byte[] key = GenerateRandomBytes(32);
                byte[] iv = GenerateRandomBytes(16);

                byte[] encrypted = Encrypt(originalText, key, iv, aes);
                string decrypted = Decrypt(encrypted, key, iv, aes);

                PrintResult(key, iv, encrypted, decrypted);
            }

            Console.ReadLine();
        }

        // Криптостійка випадкова послідовність байтів (для ключа та IV)
        static byte[] GenerateRandomBytes(int length)
        {
            byte[] randomBytes = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }

        // Зашифровування
        static byte[] Encrypt(string plainText, byte[] key, byte[] iv, SymmetricAlgorithm algorithm)
        {
            algorithm.Key = key;
            algorithm.IV = iv;

            ICryptoTransform encryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }

        // Розшифровування
        static string Decrypt(byte[] cipherText, byte[] key, byte[] iv, SymmetricAlgorithm algorithm)
        {
            algorithm.Key = key;
            algorithm.IV = iv;

            ICryptoTransform decryptor = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV);

            using (MemoryStream msDecrypt = new MemoryStream(cipherText))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        return srDecrypt.ReadToEnd();
                    }
                }
            }
        }

        static void PrintResult(byte[] key, byte[] iv, byte[] encrypted, string decrypted)
        {
            Console.WriteLine($"Ключ         : {Convert.ToBase64String(key)}");
            Console.WriteLine($"Вектор (IV)  : {Convert.ToBase64String(iv)}");
            Console.WriteLine($"Зашифровано  : {Convert.ToBase64String(encrypted)}");
            Console.WriteLine($"Розшифровано : {decrypted}\n");
        }
    }
}

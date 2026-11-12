using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab5_2
{
    class Program
    {
        // Число ітерацій = номер варіанта * 10 000
        const int Variant = 9;
        const int Iterations = Variant * 10000;   // 90 000

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            string originalText = "Сьогодні гарна погода";
            string password = "SecretPassword";

            Console.WriteLine($"Оригінальний текст\n{originalText}");
            Console.WriteLine($"Пароль: {password}");
            Console.WriteLine($"Кількість ітерацій: {Iterations}\n");

            // Сіль - випадкова послідовність байтів
            byte[] salt = GenerateRandomBytes(16);
            Console.WriteLine($"Сіль (Base64): {Convert.ToBase64String(salt)}\n");

            // Алгоритм DES: ключ 8 байт, IV 8 байт
            Console.WriteLine("Алгоритм DES");
            using (DES des = DES.Create())
            {
                Process(originalText, password, salt, des, 8, 8);
            }

            // Алгоритм Triple-DES: ключ 24 байти, IV 8 байт
            Console.WriteLine("Алгоритм Triple-DES");
            using (TripleDES tdes = TripleDES.Create())
            {
                Process(originalText, password, salt, tdes, 24, 8);
            }

            // Алгоритм AES: ключ 32 байти, IV 16 байт
            Console.WriteLine("Алгоритм AES");
            using (Aes aes = Aes.Create())
            {
                Process(originalText, password, salt, aes, 32, 16);
            }

            Console.ReadLine();
        }

        // Зашифровує, потім розшифровує, щоразу виводячи ключ та IV з пароля і солі
        static void Process(string text, string password, byte[] salt,
                            SymmetricAlgorithm algorithm, int keySize, int ivSize)
        {
            byte[] key, iv;
            DeriveKeyAndIv(password, salt, keySize, ivSize, out key, out iv);
            byte[] encrypted = Encrypt(text, key, iv, algorithm);

            // Для розшифровування ключ та IV знову відновлюємо з пароля і солі
            DeriveKeyAndIv(password, salt, keySize, ivSize, out byte[] key2, out byte[] iv2);
            string decrypted = Decrypt(encrypted, key2, iv2, algorithm);

            PrintResult(key, iv, encrypted, decrypted);
        }

        // Ключ та IV з пароля через Rfc2898DeriveBytes (PBKDF2)
        static void DeriveKeyAndIv(string password, byte[] salt, int keySize, int ivSize,
                                   out byte[] key, out byte[] iv)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                key = deriveBytes.GetBytes(keySize);
                iv = deriveBytes.GetBytes(ivSize);
            }
        }

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

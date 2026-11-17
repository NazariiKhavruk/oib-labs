using System;
using System.Security.Cryptography;
using System.Text;

namespace Lab6_1
{
    class Program
    {
        // Пара ключів зберігається у пам'яті
        private static RSAParameters _publicKey, _privateKey;

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            string originalText = "Сьогодні гарна погода";

            AssignNewKey();

            byte[] encrypted = EncryptData(Encoding.UTF8.GetBytes(originalText));
            byte[] decrypted = DecryptData(encrypted);

            Console.WriteLine("Асиметричне шифрування RSA (ключі у пам'яті)\n");
            Console.WriteLine($"Довжина ключа : {_publicKey.Modulus!.Length * 8} біт");
            Console.WriteLine($"Відкритий ключ (Modulus): {Convert.ToBase64String(_publicKey.Modulus)}");
            Console.WriteLine($"Відкритий ключ (Exponent): {Convert.ToBase64String(_publicKey.Exponent!)}\n");
            Console.WriteLine($"Оригінальний текст : {originalText}");
            Console.WriteLine($"Зашифровано        : {Convert.ToBase64String(encrypted)}");
            Console.WriteLine($"Розшифровано       : {Encoding.UTF8.GetString(decrypted)}");

            Console.ReadLine();
        }

        // Генерація пари ключів RSA 2048 біт
        public static void AssignNewKey()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                _publicKey = rsa.ExportParameters(false);
                _privateKey = rsa.ExportParameters(true);
            }
        }

        // Зашифровування відкритим ключем
        public static byte[] EncryptData(byte[] dataToEncrypt)
        {
            byte[] cypherBytes;
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_publicKey);
                cypherBytes = rsa.Encrypt(dataToEncrypt, true);   // true - доповнення OAEP
            }
            return cypherBytes;
        }

        // Розшифровування секретним ключем
        public static byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plainBytes;
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(_privateKey);
                plainBytes = rsa.Decrypt(dataToDecrypt, true);
            }
            return plainBytes;
        }
    }
}

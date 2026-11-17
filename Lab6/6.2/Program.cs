using System;
using System.Security.Cryptography;
using System.Text;

namespace Lab6_2
{
    class Program
    {
        // Пара ключів зберігається у контейнері ключів (CSP) на рівні пристрою
        private readonly static string CspContainerName = "RsaContainer";

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            string originalText = "Сьогодні гарна погода";

            AssignNewKey();

            byte[] encrypted = EncryptData(Encoding.UTF8.GetBytes(originalText));
            byte[] decrypted = DecryptData(encrypted);

            Console.WriteLine("Асиметричне шифрування RSA (ключі у контейнері)\n");
            Console.WriteLine($"Контейнер ключів   : {CspContainerName}");
            Console.WriteLine($"Оригінальний текст : {originalText}");
            Console.WriteLine($"Зашифровано        : {Convert.ToBase64String(encrypted)}");
            Console.WriteLine($"Розшифровано       : {Encoding.UTF8.GetString(decrypted)}\n");

            // Після роботи ключі видаляються із сховища
            DeleteKeyInCsp();
            Console.WriteLine("Ключі видалено з контейнера");

            Console.ReadLine();
        }

        // Генерація пари ключів та збереження у іменованому контейнері
        public static void AssignNewKey()
        {
            CspParameters cspParameters = new CspParameters(1)
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore,   // рівень пристрою
                ProviderName = "Microsoft Strong Cryptographic Provider"
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
            {
                rsa.PersistKeyInCsp = true;
            }
        }

        // Зашифровування ключем із контейнера
        public static byte[] EncryptData(byte[] dataToEncrypt)
        {
            byte[] cypherBytes;
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            using (var rsa = new RSACryptoServiceProvider(cspParams))
            {
                rsa.PersistKeyInCsp = true;
                cypherBytes = rsa.Encrypt(dataToEncrypt, true);
            }
            return cypherBytes;
        }

        // Розшифровування ключем із контейнера
        public static byte[] DecryptData(byte[] dataToDecrypt)
        {
            byte[] plainBytes;
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            using (var rsa = new RSACryptoServiceProvider(cspParams))
            {
                rsa.PersistKeyInCsp = true;
                plainBytes = rsa.Decrypt(dataToDecrypt, true);
            }
            return plainBytes;
        }

        // Видалення ключів із контейнера
        public static void DeleteKeyInCsp()
        {
            CspParameters cspParameters = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            var rsa = new RSACryptoServiceProvider(cspParameters)
            {
                PersistKeyInCsp = false
            };
            rsa.Clear();
        }
    }
}

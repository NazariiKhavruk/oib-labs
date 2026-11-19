using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab7_1
{
    class Program
    {
        // Секретний ключ зберігається у контейнері, відкритий - у XML-файлі
        private readonly static string CspContainerName = "RsaContainer";
        private readonly static string PublicKeyPath = "public_key.xml";

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            string message = "Сьогодні чудова погода";

            // Генеруємо ключі у контейнері та зберігаємо відкритий ключ у файл
            GenerateOwnKeys(PublicKeyPath);

            // Підписування секретним ключем із контейнера
            byte[] signature = SignData(Encoding.UTF8.GetBytes(message));

            Console.WriteLine("Електронний цифровий підпис RSA (SHA-512)\n");
            Console.WriteLine($"Відкритий ключ : {Path.GetFullPath(PublicKeyPath)}");
            Console.WriteLine($"Повідомлення   : {message}");
            Console.WriteLine($"ЕЦП            : {Convert.ToBase64String(signature)}\n");

            // Перевірка відкритим ключем із XML-файлу
            bool verified = VerifySignature(PublicKeyPath, Encoding.UTF8.GetBytes(message), signature);
            Console.WriteLine($"Перевірка оригінального повідомлення: {(verified ? "підпис вірний" : "підпис невірний")}");

            // Повідомлення змінили після підписання - підпис має не пройти
            string changedMessage = "Сьогодні погана погода";
            bool verifiedChanged = VerifySignature(PublicKeyPath, Encoding.UTF8.GetBytes(changedMessage), signature);
            Console.WriteLine($"Перевірка зміненого повідомлення \"{changedMessage}\": {(verifiedChanged ? "підпис вірний" : "підпис невірний")}");

            Console.ReadLine();
        }

        // Генерація ключів у контейнері та збереження відкритого ключа у XML-файл
        public static void GenerateOwnKeys(string publicKeyPath)
        {
            CspParameters cspParameters = new CspParameters(1)
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore,
                ProviderName = "Microsoft Strong Cryptographic Provider"
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
            {
                rsa.PersistKeyInCsp = true;
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));
            }
        }

        // Створення ЕЦП
        public static byte[] SignData(byte[] dataToSign)
        {
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
            {
                // Використовуємо секретний ключ із контейнера
                rsa.PersistKeyInCsp = true;

                var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
                rsaFormatter.SetHashAlgorithm(nameof(SHA512));

                // Спочатку хеш-код повідомлення, підписуємо вже його
                byte[] hashOfData;
                using (var sha512 = SHA512.Create())
                {
                    hashOfData = sha512.ComputeHash(dataToSign);
                }
                return rsaFormatter.CreateSignature(hashOfData);
            }
        }

        // Перевірка ЕЦП
        public static bool VerifySignature(string publicKeyPath, byte[] data, byte[] signature)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                // Використовуємо відкритий ключ із XML-файлу
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));

                var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
                rsaDeformatter.SetHashAlgorithm(nameof(SHA512));

                byte[] hashOfData;
                using (var sha512 = SHA512.Create())
                {
                    hashOfData = sha512.ComputeHash(data);
                }
                return rsaDeformatter.VerifySignature(hashOfData, signature);
            }
        }
    }
}

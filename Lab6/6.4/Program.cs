using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab6_4
{
    class Program
    {
        // Окремий контейнер, щоб секретний ключ не загубився, поки чекаю вітання від інших
        private readonly static string CspContainerName = "KhavrukContainer";
        // Ім'я файлу - транслітерація прізвища (Хаврук)
        private readonly static string PublicKeyPath = "Khavruk.xml";

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.WriteLine();
                Console.WriteLine($"1. Згенерувати ключ RSA 2048 біт та зберегти відкритий ключ у {PublicKeyPath}");
                Console.WriteLine("2. Зашифрувати вітання для студента (його файл .xml)");
                Console.WriteLine("3. Розшифрувати отримане вітання (файл .dat або текст Base64)");
                Console.WriteLine("0. Вихід");
                Console.Write("Оберіть дію: ");

                switch (Console.ReadLine())
                {
                    case "1":
                        GenerateOwnKeys(PublicKeyPath);
                        Console.WriteLine($"Відкритий ключ збережено: {Path.GetFullPath(PublicKeyPath)}");
                        break;

                    case "2":
                        SendGreeting();
                        break;

                    case "3":
                        ReadGreeting();
                        break;

                    case "0":
                        return;

                    default:
                        Console.WriteLine("Невірний вибір.");
                        break;
                }
            }
        }

        static void SendGreeting()
        {
            Console.Write("Файл відкритого ключа студента (наприклад Shkonda.xml): ");
            string keyPath = Console.ReadLine() ?? "";
            if (!File.Exists(keyPath))
            {
                Console.WriteLine("Файл не знайдено.");
                return;
            }

            Console.Write("Текст вітання (Enter - стандартне): ");
            string? text = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(text))
                text = "Привіт! Вітання від Назарія Хаврука";

            // Ім'я файлу: Khavruk_to_Shkonda.dat
            string receiver = Path.GetFileNameWithoutExtension(keyPath);
            string cipherPath = $"Khavruk_to_{receiver}.dat";

            EncryptData(keyPath, Encoding.UTF8.GetBytes(text), cipherPath);

            Console.WriteLine($"Вітання для {receiver} зашифровано.");
            Console.WriteLine($"Файл: {Path.GetFullPath(cipherPath)}");
            Console.WriteLine($"Base64 (можна вставити в чат):\n{Convert.ToBase64String(File.ReadAllBytes(cipherPath))}");
        }

        static void ReadGreeting()
        {
            Console.Write("Шлях до файлу .dat або текст Base64: ");
            string input = (Console.ReadLine() ?? "").Trim();

            byte[] chipherBytes;
            try
            {
                chipherBytes = File.Exists(input) ? File.ReadAllBytes(input) : Convert.FromBase64String(input);
            }
            catch (FormatException)
            {
                Console.WriteLine("Це не файл і не текст Base64.");
                return;
            }

            try
            {
                byte[] plain = DecryptData(chipherBytes);
                Console.WriteLine($"Отримане вітання: {Encoding.UTF8.GetString(plain)}");
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Не вдалося розшифрувати: вітання зашифроване не моїм відкритим ключем.");
            }
        }

        // Генерація ключів у контейнері та збереження відкритого ключа у файл
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
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));   // лише відкритий (!!!) ключ
            }
        }

        // Зашифровування відкритим ключем іншого студента
        public static void EncryptData(string publicKeyPath, byte[] dataToEncrypt, string chipherTextPath)
        {
            byte[] chipherBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                chipherBytes = rsa.Encrypt(dataToEncrypt, true);
            }
            File.WriteAllBytes(chipherTextPath, chipherBytes);
        }

        // Розшифровування своїм секретним ключем із контейнера
        public static byte[] DecryptData(byte[] chipherBytes)
        {
            byte[] plainTextBytes;
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
            {
                rsa.PersistKeyInCsp = true;
                plainTextBytes = rsa.Decrypt(chipherBytes, true);
            }
            return plainTextBytes;
        }
    }
}

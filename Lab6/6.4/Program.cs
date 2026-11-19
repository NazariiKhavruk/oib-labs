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
        // Ім'я файлу - транслітерація прізвища
        private readonly static string PublicKeyPath = "Khavruk.xml";

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.WriteLine();
                Console.WriteLine($"1. Створити ключі ({PublicKeyPath})");
                Console.WriteLine("2. Зашифрувати вітання");
                Console.WriteLine("3. Розшифрувати вітання");
                Console.WriteLine("0. Вихід");
                Console.Write("Дія: ");

                switch (Console.ReadLine())
                {
                    case "1":
                        GenerateOwnKeys(PublicKeyPath);
                        Console.WriteLine($"Відкритий ключ: {Path.GetFullPath(PublicKeyPath)}");
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

        // Прибираємо пробіли та лапки (Windows "Копіювати як шлях" додає лапки)
        static string ReadPath()
        {
            return (Console.ReadLine() ?? "").Trim().Trim('"');
        }

        static void SendGreeting()
        {
            Console.Write("Ключ отримувача (.xml): ");
            string keyPath = ReadPath();
            if (!File.Exists(keyPath))
            {
                Console.WriteLine("Файл не знайдено.");
                return;
            }

            Console.Write("Текст (Enter - стандартний): ");
            string? text = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(text))
                text = "Привіт! Вітаю з лабораторною з RSA";

            // Ім'я файлу: To_<ім'я ключа отримувача>.dat
            string receiver = Path.GetFileNameWithoutExtension(keyPath);
            string cipherPath = $"To_{receiver}.dat";

            EncryptData(keyPath, Encoding.UTF8.GetBytes(text), cipherPath);

            Console.WriteLine($"Збережено: {Path.GetFullPath(cipherPath)}");
            Console.WriteLine($"Base64:\n{Convert.ToBase64String(File.ReadAllBytes(cipherPath))}");
        }

        static void ReadGreeting()
        {
            Console.Write("Файл .dat або Base64: ");
            string input = ReadPath();
            if (input == "")
            {
                Console.WriteLine("Нічого не введено.");
                return;
            }

            byte[] chipherBytes;
            try
            {
                chipherBytes = File.Exists(input) ? File.ReadAllBytes(input) : Convert.FromBase64String(input);
            }
            catch (FormatException)
            {
                Console.WriteLine("Файл не знайдено.");
                return;
            }

            try
            {
                byte[] plain = DecryptData(chipherBytes);
                Console.WriteLine($"Вітання: {Encoding.UTF8.GetString(plain)}");
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Не розшифровано: зашифровано не моїм ключем.");
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

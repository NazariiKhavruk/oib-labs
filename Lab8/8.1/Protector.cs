using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;

namespace Lab8_1
{
    // Автентифікація та авторизація користувачів
    public static class Protector
    {
        // Число ітерацій = номер варіанта * 10 000
        const int Variant = 9;
        const int Iterations = Variant * 10000;   // 90 000

        // Зареєстровані користувачі
        private static Dictionary<string, User> _users = new Dictionary<string, User>();

        // Реєстрація користувача
        public static User? Register(string userName, string password, string[]? roles = null)
        {
            // Перевірка, що користувач з таким іменем ще не зареєстрований
            if (_users.ContainsKey(userName))
            {
                Console.WriteLine($"Користувач {userName} вже зареєстрований.");
                return null;
            }

            // Генерація солі
            byte[] saltBytes = new byte[16];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(saltBytes);
            }
            string salt = Convert.ToBase64String(saltBytes);

            // Хеш пароля
            string passwordHash = ComputeHash(password, saltBytes);

            var user = new User
            {
                Login = userName,
                PasswordHash = passwordHash,
                Salt = salt,
                Roles = roles ?? new string[0]
            };
            _users.Add(userName, user);
            return user;
        }

        // Перевірка пароля
        public static bool CheckPassword(string userName, string password)
        {
            // Перевірка, що користувач з таким іменем зареєстрований
            if (!_users.ContainsKey(userName))
            {
                return false;
            }

            User user = _users[userName];

            // Хеш уведеного пароля з тією ж сіллю
            string hash = ComputeHash(password, Convert.FromBase64String(user.Salt));

            // Порівнюємо з хешем, що зберігається
            return hash == user.PasswordHash;
        }

        // Автентифікація користувача
        public static void LogIn(string userName, string password)
        {
            if (CheckPassword(userName, password))
            {
                // Екземпляр автентифікованого користувача
                var identity = new GenericIdentity(userName, "OIBAuth");
                // Прив'язка до ролей користувача
                var principal = new GenericPrincipal(identity, _users[userName].Roles);
                // Присвоюємо потоку, в якому виконується програма
                Thread.CurrentPrincipal = principal;
            }
        }

        // Метод лише для користувачів з роллю "Admins"
        public static void OnlyForAdminsFeature()
        {
            // Перевірка, що потік виконується автентифікованим користувачем
            if (Thread.CurrentPrincipal == null)
            {
                throw new SecurityException("Thread.CurrentPrincipal cannot be null.");
            }

            // Перевірка, що користувач належить до ролі "Admins"
            if (!Thread.CurrentPrincipal.IsInRole("Admins"))
            {
                throw new SecurityException("User must be a member of Admins to access this feature.");
            }

            // Захищена частина програми
            Console.WriteLine("You have access to this secure feature.");
        }

        // Хеш пароля через Rfc2898DeriveBytes (PBKDF2)
        private static string ComputeHash(string password, byte[] salt)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, Iterations, HashAlgorithmName.SHA256))
            {
                return Convert.ToBase64String(deriveBytes.GetBytes(32));
            }
        }
    }
}

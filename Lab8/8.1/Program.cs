using System;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Lab8_1
{
    class Program
    {
        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            // Реєстрація чотирьох користувачів з різними ролями
            Protector.Register("Alice", "password", new[] { "Admins" });
            Protector.Register("Bob", "password", new[] { "Admins", "Sales" });
            Protector.Register("Charlie", "password", new[] { "Sales" });
            Protector.Register("Eve", "password");

            Console.WriteLine("Зареєстровано: Alice (Admins), Bob (Admins, Sales), Charlie (Sales), Eve (без ролей)");

            while (true)
            {
                Console.WriteLine();
                Console.Write("Логін (Enter - вихід): ");
                string userName = Console.ReadLine() ?? "";
                if (userName == "")
                    return;

                Console.Write("Пароль: ");
                string password = Console.ReadLine() ?? "";

                // Попередній користувач виходить
                Thread.CurrentPrincipal = null;

                Protector.LogIn(userName, password);

                IPrincipal? p = Thread.CurrentPrincipal;
                if (p == null)
                {
                    Console.WriteLine("Невірний логін або пароль.");
                }
                else
                {
                    Console.WriteLine($"Name: {p.Identity!.Name}");
                    Console.WriteLine($"IsAuthenticated: {p.Identity.IsAuthenticated}");
                    Console.WriteLine($"AuthenticationType: {p.Identity.AuthenticationType}");
                    Console.WriteLine($"IsInRole(\"Admins\"): {p.IsInRole("Admins")}");
                }

                // Спроба виконати захищений метод
                try
                {
                    Protector.OnlyForAdminsFeature();
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"{ex.GetType()}: {ex.Message}");
                }
            }
        }
    }
}

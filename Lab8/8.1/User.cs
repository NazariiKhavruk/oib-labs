namespace Lab8_1
{
    // Користувач системи
    public class User
    {
        public string Login { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string Salt { get; set; } = "";
        public string[] Roles { get; set; } = new string[0];
    }
}

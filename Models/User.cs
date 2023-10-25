namespace jsonwebtoken_aspnet.Models
{
    public class User
    {
        public String Username { get; set; } = string.Empty;
        public String? PasswordHash { get; set; }
    }
}
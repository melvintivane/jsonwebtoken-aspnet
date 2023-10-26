using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BCrypt.Net;
using jsonwebtoken_aspnet.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace jsonwebtoken_aspnet.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : Controller
    {
        public static User user = new();
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost("register")]
        public ActionResult<User> Register(UserDTO request)
        {
            try
            {
                string hashPassword = BCrypt.Net.BCrypt.HashPassword(request.Password);
                user.Username = request.Username;
                user.PasswordHash = hashPassword;

                return Ok(user);
            }
            catch (System.Exception)
            {
                throw;
            }
        }

        [HttpPost("login")]
        public ActionResult<User> Login(UserDTO request)
        {
            try
            {
                if (user.Username != request.Username)
                {
                    return BadRequest("Wrong Password or Username.");
                }

                if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                {
                    return BadRequest("Wrong Password or Username.");
                }

                string token = CreateToken(user);
                return Ok(token);
            }
            catch (System.Exception)
            {
                throw;
            }
        }

        [HttpPost]
        private string CreateToken(User user) //precisamos do user para gerar os claims
        {
            try
            {
                List<Claim> claims = new()
                {
                    new(ClaimTypes.Name, user.Username)
                };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("AppSettings:Token").Value!));

                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

                var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: credentials
                );

                var JWT = new JwtSecurityTokenHandler().WriteToken(token);

                return JWT;
            }
            catch (System.Exception)
            {
                throw;
            }
        }
    }
}
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace JWTAuthentication.Services
{
    public class JwtTokenGenerator
    {
        private readonly IConfiguration _configuration;


        public JwtTokenGenerator(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        private class User
        {
            public User (int userId, string userName, string firstName, string lastName)
            {
                UserId = userId;
                UserName = userName;
                FirstName = firstName;
                LastName = lastName;
            }
            public string LastName { get; set; }

            public string FirstName { get; set; }

            public string UserName { get; set; }

            public int UserId { get; set; }
        }
        
        public string GenerateToken(LoginRequest loginRequest)
        {
            var user = ValidateUserCredentials(loginRequest.Username, loginRequest.Password);
            if (user == null)
            {
                return null;
            }
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
                new Claim("given_name", user. FirstName),
                new Claim("family_name", user.LastName),
                new Claim("UserName", user.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Authentication:SecretForKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Authentication:Issuer"],
                audience: _configuration["Authentication:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        public ClaimsPrincipal? ValidateToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer =_configuration["Authentication:Issuer"],
                ValidAudience = _configuration["Authentication:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Authentication:SecretForKey"]))
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return principal;
            }
            catch
            {
                return null;
            }
        }
        private User ValidateUserCredentials(string username, string password)
        {
            return new User(
                1,
                username ?? "",
                "Omar",
                "Khalili"
                );
        }
    }
}
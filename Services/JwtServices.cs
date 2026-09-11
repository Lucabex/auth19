using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using auth19.Models;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;

namespace auth19.Services;

public class JwtService
{
    private readonly IConfiguration _config;
    private readonly SymmetricSecurityKey _key;

    public JwtService(IConfiguration config)
    {
        _config = config;
        var secretKey = _config["JwtSettings:SecretKey"];
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!));
    }
    public string GenerateToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier,user.id.ToString()),
            new Claim(ClaimTypes.Name,(user.Name ?? "Unknown")),
            new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Audience = _config["JwtSettings:Audience"],
            Issuer = _config["JwtSettings:Issuer"],
            Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(_config["JwtSettings:ExpInMinutes"])),
            SigningCredentials =new SigningCredentials(_key,SecurityAlgorithms.HmacSha256)
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var token=tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
    
}
}
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthentication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<JwtTokenGenerator>(sp =>
{
    return new JwtTokenGenerator(builder.Configuration);
});
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Authentication:Issuer"],
            ValidAudience = builder.Configuration["Authentication:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Authentication:SecretForKey"]))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication(); 
app.UseAuthorization();

app.MapGet("/",()=>"Hello World");
app.MapGet("/secret", () => "This is protected")
    .RequireAuthorization();

app.MapPost("/login", ([FromBody] LoginRequest login, JwtTokenGenerator tokenGenerator) =>
{
   
    var token = tokenGenerator.GenerateToken(login.Username);
    return Results.Ok(new { token });
});


app.Run();

public record LoginRequest(string Username, string Password);

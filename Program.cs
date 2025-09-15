using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ProductManagementAPI.Data;
using ProductManagementAPI.Services;
using ProductManagementAPI.DTOs;
using ProductManagementAPI.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.OpenApi.Models;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// --- Banco de Dados ---
builder.Services.AddDbContext<ProductDbContext>(options =>
    options.UseSqlite("Data Source=products.db"));

// --- Serviço ---
builder.Services.AddScoped<ProductService>();

// --- JWT Authentication ---
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var jwtSettings = builder.Configuration.GetSection("Jwt");
        var key = Encoding.UTF8.GetBytes(jwtSettings["Key"] ?? "");

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key)
        };
    });

builder.Services.AddAuthorization();

// --- Swagger ---
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Insira o token JWT desta forma: Bearer {seu token}"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

var app = builder.Build();

// --- Pipeline ---
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Product Management API v1");
    c.RoutePrefix = string.Empty; // Swagger na raiz: http://localhost:5000
});

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// --- Endpoints ---
app.MapGet("/", () => Results.Ok(new
{
    message = "Bem-vindo à Product Management API!",
    endpoints = new[]
    {
        "GET /health",
        "GET /products",
        "POST /products",
        "PUT /products/{id}",
        "DELETE /products/{id}",
        "POST /login"
    },
    swagger = "http://localhost:5000"
}));

app.MapGet("/health", () => "Healthy").AllowAnonymous();

// --- JWT Login Endpoint ---
app.MapPost("/login", (HttpContext context, [FromBody] User login) =>
{
    var configuration = context.RequestServices.GetRequiredService<IConfiguration>();

    if (login.Username == "admin" && login.Password == "senha123")
    {
        var key = Encoding.UTF8.GetBytes(configuration["Jwt:Key"] ?? "");
        var issuer = configuration["Jwt:Issuer"];
        var audience = configuration["Jwt:Audience"];

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, login.Username),
                new Claim(ClaimTypes.Role, "Admin")
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = issuer,
            Audience = audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var jwtToken = tokenHandler.WriteToken(token);

        return Results.Ok(new
        {
            token = jwtToken,
            expires = tokenDescriptor.Expires
        });
    }

    return Results.Unauthorized();
}).AllowAnonymous();

// --- Produtos (protegidos por JWT) ---
app.MapGet("/products", async (ProductService service) =>
{
    var products = await service.GetAllAsync();
    return Results.Ok(products);
}).RequireAuthorization();

app.MapGet("/products/{id}", async (int id, ProductService service) =>
{
    var product = await service.GetByIdAsync(id);
    return product is null ? Results.NotFound() : Results.Ok(product);
}).RequireAuthorization();

app.MapPost("/products", async (ProductDTO dto, ProductService service) =>
{
    var product = new Product
    {
        Name = dto.Name,
        Description = dto.Description,
        Price = dto.Price
    };
    await service.AddAsync(product);
    return Results.Created($"/products/{product.Id}", product);
}).RequireAuthorization();

app.MapPut("/products/{id}", async (int id, ProductDTO dto, ProductService service) =>
{
    var existingProduct = await service.GetByIdAsync(id);
    if (existingProduct is null) return Results.NotFound();

    existingProduct.Name = dto.Name;
    existingProduct.Description = dto.Description;
    existingProduct.Price = dto.Price;

    await service.UpdateAsync(existingProduct);
    return Results.NoContent();
}).RequireAuthorization();

app.MapDelete("/products/{id}", async (int id, ProductService service) =>
{
    var existingProduct = await service.GetByIdAsync(id);
    if (existingProduct is null) return Results.NotFound();

    await service.DeleteAsync(id);
    return Results.NoContent();
}).RequireAuthorization();

app.Run();
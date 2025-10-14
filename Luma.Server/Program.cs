using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Repositories;
using Luma.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using System.Reflection;
using Luma.Infrastructure.Extensions;
using Luma.Infrastructure.Data;

// Ensure config file exists (create from embedded resource if missing)
if (!File.Exists("luma.config.json"))
{
    using var stream = Assembly.GetExecutingAssembly()
        .GetManifestResourceStream("Luma.Server.luma.config.json");
    if (stream == null)
        throw new InvalidOperationException("Embedded default configuration not found.");

    using var reader = new StreamReader(stream);
    var json = reader.ReadToEnd();
    File.WriteAllText("luma.config.json", json);
}

var builder = WebApplication.CreateBuilder(args);

// Build configuration
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("luma.config.json", optional: false, reloadOnChange: true)
    .AddEnvironmentVariables();

builder.Services.Configure<LumaOptions>(
    builder.Configuration.GetSection("Luma"));

// Configure database
var lumaConfig = builder.Configuration.GetSection("Luma").Get<LumaOptions>()!;
var databaseConfig = lumaConfig.Database;
if (string.IsNullOrWhiteSpace(databaseConfig.Provider))
    throw new Exception("Database provider is missing in configuration.");

if (string.IsNullOrWhiteSpace(databaseConfig.ConnectionString))
    throw new Exception("Database connection string is missing.");

switch (databaseConfig.Provider.Trim().ToLowerInvariant())
{
    case "sqlite":
    case "microsoft.entityframeworkcore.sqlite":
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlite(databaseConfig.ConnectionString));
        break;

    case "postgres":
    case "npgsql":
    case "microsoft.entityframeworkcore.postgresql":
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseNpgsql(databaseConfig.ConnectionString));
        break;

    case "sqlserver":
    case "microsoft.entityframeworkcore.sqlserver":
        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(databaseConfig.ConnectionString));
        break;

    default:
        throw new Exception($"Unsupported database provider: {databaseConfig.Provider}");
}

// Register services
builder.Services.AddLumaSecurity();
builder.Services.AddLumaRepositories();
builder.Services.AddControllers();

// Build app
var app = builder.Build();

// Use Middlewares
app.UseHttpsRedirection();
app.MapControllers();
app.Run();

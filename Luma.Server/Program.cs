using Luma.Core.Extensions;
using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Data;
using Luma.Infrastructure.Extensions;
using Luma.Infrastructure.Repositories;
using Luma.Infrastructure.Security;
using Luma.Server.Utility;            // where RazorViewLocationExpander lives
using Microsoft.AspNetCore.Mvc.Razor;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using System.Reflection;

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

// Bind options
builder.Services.Configure<LumaOptions>(builder.Configuration.GetSection("Luma"));
var lumaConfig = builder.Configuration.GetSection("Luma").Get<LumaOptions>()!;

// ---------------------------
// Database
// ---------------------------
var databaseConfig = lumaConfig.Database;
if (string.IsNullOrWhiteSpace(databaseConfig.Provider))
    throw new Exception("Database provider is missing in configuration.");
if (string.IsNullOrWhiteSpace(databaseConfig.ConnectionString))
    throw new Exception("Database connection string is missing.");

switch (databaseConfig.Provider.Trim().ToLowerInvariant())
{
    case "sqlite":
    case "microsoft.entityframeworkcore.sqlite":
        builder.Services.AddDbContext<ApplicationDbContext>(o => o.UseSqlite(databaseConfig.ConnectionString));
        break;
    case "postgres":
    case "npgsql":
    case "microsoft.entityframeworkcore.postgresql":
        builder.Services.AddDbContext<ApplicationDbContext>(o => o.UseNpgsql(databaseConfig.ConnectionString));
        break;
    case "sqlserver":
    case "microsoft.entityframeworkcore.sqlserver":
        builder.Services.AddDbContext<ApplicationDbContext>(o => o.UseSqlServer(databaseConfig.ConnectionString));
        break;
    default:
        throw new Exception($"Unsupported database provider: {databaseConfig.Provider}");
}

// ---------------------------
// Core services
// ---------------------------
builder.Services.AddLumaServices();
builder.Services.AddLumaSecurity();
builder.Services.AddLumaProviders();
builder.Services.AddLumaRepositories();
builder.Services.AddLumaWeb();
builder.Services.AddControllers();
builder.Services.AddHttpContextAccessor();

// ---------------------------
// UI / Templates
// ---------------------------
var auth = lumaConfig.AuthenticationServer;

if (auth.UseAuthentication)
{
    if (auth.UseCustomFiles)
    {
        // Custom files selected
        if (auth.CustomFiles.ViewMode.Equals("Razor", StringComparison.OrdinalIgnoreCase))
        {
            builder.Services.AddRazorPages().AddRazorRuntimeCompilation();

            // Use your expander name exactly as requested
            builder.Services.Configure<RazorViewEngineOptions>(opt =>
            {
                opt.ViewLocationExpanders.Add(
                    new RazorViewLocationExpander(auth.CustomFiles.Path)
                );
            });
        }
    }
    else
    {
        // Built-in (embedded) Razor templates
        builder.Services.AddRazorPages();
    }
}

// ---------------------------
// Build app
// ---------------------------
var app = builder.Build();

// ---------------------------
// Static files (only when using custom static files)
// ---------------------------
if (auth.UseAuthentication &&
    auth.UseCustomFiles &&
    auth.CustomFiles.ViewMode.Equals("Static", StringComparison.OrdinalIgnoreCase))
{
    var root = Path.GetFullPath(auth.CustomFiles.Path ?? "./wwwroot");
    app.UseStaticFiles(new StaticFileOptions
    {
        FileProvider = new PhysicalFileProvider(root),
        RequestPath = ""
    });
}

// ---------------------------
// Middleware & endpoints
// ---------------------------
app.UseHttpsRedirection();
app.MapControllers();

// Map Razor pages only when Razor is active (built-in or custom Razor)
if (auth.UseAuthentication &&
    (!auth.UseCustomFiles || auth.CustomFiles.ViewMode.Equals("Razor", StringComparison.OrdinalIgnoreCase)))
{
    app.MapRazorPages();
}

app.Run();

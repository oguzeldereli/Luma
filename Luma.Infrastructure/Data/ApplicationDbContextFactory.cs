using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;

namespace Luma.Infrastructure.Data
{
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            // EF Core design-time runs in Infrastructure/bin/... directory,
            // so we point up to the Server project where your luma.config.json lives
            var basePath = Path.Combine(Directory.GetCurrentDirectory(), "../Luma.Server");

            var configuration = new ConfigurationBuilder()
                .SetBasePath(basePath)
                .AddJsonFile("luma.config.json", optional: false)
                .AddEnvironmentVariables()
                .Build();

            // Read database provider and connection info from config
            var provider = configuration["Luma:Database:Provider"];
            var connectionString = configuration["Luma:Database:ConnectionString"];

            if (string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(connectionString))
                throw new InvalidOperationException("Database provider or connection string missing in luma.config.json.");

            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

            switch (provider.Trim().ToLowerInvariant())
            {
                case "sqlite":
                case "microsoft.entityframeworkcore.sqlite":
                    optionsBuilder.UseSqlite(connectionString, b => b.MigrationsAssembly("Luma.Infrastructure"));
                    break;
                case "postgres":
                case "npgsql":
                case "npgsql.entityframeworkcore.postgresql":
                    optionsBuilder.UseNpgsql(connectionString, b => b.MigrationsAssembly("Luma.Infrastructure"));
                    break;
                case "sqlserver":
                case "microsoft.entityframeworkcore.sqlserver":
                    optionsBuilder.UseSqlServer(connectionString, b => b.MigrationsAssembly("Luma.Infrastructure"));
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported database provider: {provider}");
            }

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}

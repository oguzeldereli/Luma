using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using System.Reflection;

namespace Luma.Infrastructure.Data
{
    public class ApplicationDbContext : DbContext
    {
        public DbSet<User> Users => Set<User>();
        public DbSet<MagicLinkToken> MagicLinkTokens => Set<MagicLinkToken>();
        public DbSet<NumericCodeToken> NumericCodeTokens => Set<NumericCodeToken>();

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());
        }

        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            foreach (var entry in ChangeTracker.Entries<User>())
            {
                if (entry.State == EntityState.Modified)
                    entry.Entity.UpdatedAt = DateTime.UtcNow;
            }
            return base.SaveChangesAsync(cancellationToken);
        }
    }
}

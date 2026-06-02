using Luma.Core.Models.Auth;
using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class UserClientContractConfiguration : IEntityTypeConfiguration<UserClientContract>
    {
        public void Configure(EntityTypeBuilder<UserClientContract> builder)
        {
            builder.HasKey(c => c.Id);

            builder.Property(c => c.ExternalId)
                .IsRequired();

            builder.HasIndex(c => c.ExternalId)
                .IsUnique();

            builder.Property(c => c.ClientId)
                .IsRequired()
                .HasMaxLength(128);

            builder.Property(c => c.UserId)
                .IsRequired();

            builder.Property(c => c.Scope)
                .HasMaxLength(512);

            builder.Property(c => c.CreatedAt)
                .IsRequired();

            builder.Property(c => c.UpdatedAt)
                .IsRequired();

            // One consent record per (user, client).
            builder.HasIndex(c => new { c.UserId, c.ClientId })
                .IsUnique();

            builder.HasOne(c => c.User)
                .WithMany(u => u.ClientContracts)
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.ToTable("UserClientContracts");
        }
    }
}

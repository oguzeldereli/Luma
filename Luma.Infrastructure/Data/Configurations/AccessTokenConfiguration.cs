using Luma.Core.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class AccessTokenConfiguration : IEntityTypeConfiguration<AccessToken>
    {
        public void Configure(EntityTypeBuilder<AccessToken> builder)
        {
            // Primary key
            builder.HasKey(t => t.Id);

            // External ID (GUID)
            builder.Property(t => t.ExternalId)
                .IsRequired();

            // Token Hash + Key ID (for opaque mode)
            builder.Property(t => t.TokenHash)
                .IsRequired()
                .HasMaxLength(128);

            builder.Property(t => t.TokenHashKeyId)
                .IsRequired()
                .HasMaxLength(64);

            // Created / Expiration
            builder.Property(t => t.CreatedAt)
                .IsRequired();

            builder.Property(t => t.ExpiresAt)
                .IsRequired();

            // Usage tracking
            builder.Property(t => t.IsUsed)
                .IsRequired();

            builder.Property(t => t.UsedAt)
                .IsRequired(false);

            // Core claims
            builder.Property(t => t.Scope)
                .IsRequired()
                .HasMaxLength(256);

            builder.Property(t => t.Sub)
                .IsRequired()
                .HasMaxLength(64);

            builder.Property(t => t.Aud)
                .IsRequired()
                .HasMaxLength(128);

            builder.Property(t => t.Iss)
                .IsRequired()
                .HasMaxLength(256);

            builder.Property(t => t.Jti)
                .IsRequired()
                .HasMaxLength(64);

            // Relationships
            builder.HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            // Indexes
            builder.HasIndex(t => t.TokenHash).IsUnique();
            builder.HasIndex(t => t.ExternalId).IsUnique();
            builder.HasIndex(t => t.ExpiresAt);
            builder.HasIndex(t => t.UserId);
            builder.HasIndex(t => t.Jti).IsUnique();

            // Table mapping
            builder.ToTable("AccessTokens");
        }
    }
}

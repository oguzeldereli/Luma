using Luma.Core.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
    {
        public void Configure(EntityTypeBuilder<RefreshToken> builder)
        {
            // Primary key
            builder.HasKey(t => t.Id);

            // External ID (GUID)
            builder.Property(t => t.ExternalId)
                .IsRequired();

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

            // Revocation
            builder.Property(t => t.IsRevoked)
                .IsRequired();

            builder.Property(t => t.RevokedAt)
                .IsRequired(false);

            // Core claims
            builder.Property(t => t.Scope)
                .IsRequired()
                .HasMaxLength(256);

            builder.Property(t => t.Aud)
                .IsRequired()
                .HasMaxLength(128);

            builder.Property(t => t.Iss)
                .IsRequired()
                .HasMaxLength(256);

            // Relationships
            builder.HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.HasOne(t => t.AccessToken)
                .WithMany()
                .HasForeignKey(t => t.AccessTokenId)
                .OnDelete(DeleteBehavior.Cascade);

            // Indexes
            builder.HasIndex(t => t.TokenHash).IsUnique();
            builder.HasIndex(t => t.ExternalId).IsUnique();
            builder.HasIndex(t => t.ExpiresAt);
            builder.HasIndex(t => t.UserId);
            builder.HasIndex(t => t.AccessTokenId);

            // Table mapping
            builder.ToTable("RefreshTokens");
        }
    }
}

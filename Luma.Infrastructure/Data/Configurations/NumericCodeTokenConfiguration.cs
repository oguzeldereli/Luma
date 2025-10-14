using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class NumericCodeTokenConfiguration : IEntityTypeConfiguration<NumericCodeToken>
    {
        public void Configure(EntityTypeBuilder<NumericCodeToken> builder)
        {
            builder.HasKey(t => t.Id);

            builder.Property(t => t.ExternalId)
                .IsRequired();

            builder.Property(t => t.TokenHash)
                .IsRequired()
                .HasMaxLength(128);

            builder.Property(t => t.TokenHashKeyId)
                .IsRequired()
                .HasMaxLength(64);

            builder.Property(t => t.CreatedAt)
                .IsRequired();

            builder.Property(t => t.ExpiresAt)
                .IsRequired();

            builder.HasIndex(t => t.TokenHash).IsUnique();
            builder.HasIndex(t => t.ExternalId).IsUnique();
            builder.HasIndex(t => t.ExpiresAt);
            builder.HasIndex(t => t.UserId);

            builder.HasOne(t => t.User)
                .WithMany()
                .HasForeignKey(t => t.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Property(t => t.IsUsed)
                .IsRequired();

            builder.ToTable("NumericCodeTokens");
        }
    }
}

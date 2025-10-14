using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Data.Configurations
{
    public class MagicLinkTokenConfiguration : IEntityTypeConfiguration<MagicLinkToken>
    {
        public void Configure(EntityTypeBuilder<MagicLinkToken> builder)
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

            builder.ToTable("MagicLinkTokens");
        }
    }
}
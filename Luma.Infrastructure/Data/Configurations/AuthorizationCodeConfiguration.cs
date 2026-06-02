using Luma.Core.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class AuthorizationCodeConfiguration : IEntityTypeConfiguration<AuthorizationCode>
    {
        public void Configure(EntityTypeBuilder<AuthorizationCode> builder)
        {
            // The opaque authorization code is the primary key (single-use, unique).
            builder.HasKey(c => c.Code);

            builder.Property(c => c.Code)
                .HasMaxLength(128);

            builder.Property(c => c.ClientId)
                .IsRequired()
                .HasMaxLength(128);

            builder.Property(c => c.Resource)
                .HasMaxLength(256);

            builder.Property(c => c.RedirectUri)
                .HasMaxLength(2048);

            builder.Property(c => c.Scope)
                .HasMaxLength(512);

            builder.Property(c => c.CodeChallenge)
                .HasMaxLength(256);

            builder.Property(c => c.CodeChallengeMethod)
                .HasMaxLength(16);

            builder.Property(c => c.Nonce)
                .HasMaxLength(256);

            builder.HasIndex(c => c.ExpiresAt);

            builder.ToTable("AuthorizationCodes");
        }
    }
}

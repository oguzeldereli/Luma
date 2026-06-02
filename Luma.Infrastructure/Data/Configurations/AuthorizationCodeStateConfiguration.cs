using Luma.Core.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class AuthorizationCodeStateConfiguration : IEntityTypeConfiguration<AuthorizationCodeState>
    {
        public void Configure(EntityTypeBuilder<AuthorizationCodeState> builder)
        {
            builder.HasKey(s => s.Id);

            builder.Property(s => s.Id)
                .HasMaxLength(64);

            builder.Property(s => s.ClientId)
                .HasMaxLength(128);

            builder.Property(s => s.DataJson)
                .IsRequired();

            builder.Property(s => s.ExpiresAtUtc)
                .IsRequired();

            builder.HasIndex(s => s.ExpiresAtUtc);

            builder.ToTable("AuthorizationCodeStates");
        }
    }
}

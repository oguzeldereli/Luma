using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Luma.Infrastructure.Data.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.HasKey(u => u.Id);

            builder.Property(u => u.ExternalId)
                .IsRequired();

            builder.HasIndex(u => u.ExternalId)
                .IsUnique();

            builder.Property(u => u.Username)
                .HasMaxLength(64);

            builder.Property(u => u.FirstName)
                .HasMaxLength(64);

            builder.Property(u => u.LastName)
                .HasMaxLength(64);

            builder.Property(u => u.PathToProfileImage)
                .HasMaxLength(256);

            builder.Property(u => u.ProfileImageUrl)
                .HasMaxLength(512);

            builder.Property(u => u.Email)
                .IsRequired()
                .HasMaxLength(256);

            builder.HasIndex(u => u.Email)
                .IsUnique();

            builder.Property(u => u.Phone)
                .HasMaxLength(32);

            builder.Property(u => u.Locale)
                .HasMaxLength(16);

            builder.Property(u => u.CreatedAt)
                .IsRequired();

            builder.Property(u => u.UpdatedAt)
                .IsRequired();

            builder.Property(u => u.Status)
                .HasConversion<string>()
                .HasMaxLength(32);

            builder.ToTable("Users");
        }
    }
}

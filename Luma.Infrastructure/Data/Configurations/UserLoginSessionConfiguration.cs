using Luma.Core.Models.Auth;
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
    public class UserLoginSessionConfiguration : IEntityTypeConfiguration<UserLoginSession>
    {
        public void Configure(EntityTypeBuilder<UserLoginSession> builder)
        {
            builder.HasKey(s => s.Id);

            builder.Property(s => s.ExternalId)
                .IsRequired();

            builder.HasIndex(s => s.ExternalId)
                .IsUnique();

            builder.Property(s => s.UserId)
                .IsRequired();

            builder.Property(s => s.CreatedAtUtc)
                .IsRequired();

            builder.Property(s => s.LastActivityUtc)
                .IsRequired();

            builder.Property(s => s.ExpiresAtUtc)
                .IsRequired(false);

            builder.Property(s => s.IsActive)
                .HasDefaultValue(true);

            builder.Property(s => s.IpAddress)
                .HasMaxLength(64);

            builder.Property(s => s.UserAgent)
                .HasMaxLength(512);

            builder.Property(s => s.ClientId)
                .HasMaxLength(128);

            builder.Property(s => s.AuthMethod)
                .HasMaxLength(64);

            builder.Property(s => s.SessionTokenHash)
                .HasMaxLength(256);

            builder.HasIndex(s => s.UserId);
            builder.HasIndex(s => s.SessionTokenHash)
                   .IsUnique(true);

            builder.HasOne<User>()
                    .WithMany(u => u.LoginSessions)
                    .HasForeignKey(s => s.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
        }
    }

}

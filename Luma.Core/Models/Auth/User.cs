using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Luma.Models.Auth
{
    public class User
    {
        public enum UserStatus
        {
            Active,
            Inactive,
            Suspended,
            Deleted
        }

        public long Id { get; set; }
        public Guid ExternalId { get; set; }
        public string? Username { get; set; } = default!;
        public string? FirstName { get; set; } = default!;
        public string? LastName { get; set; } = default!;
        public string? PathToProfileImage { get; set; } = string.Empty;
        public string? ProfileImageUrl { get; set; } = string.Empty;
        public string Email { get; set; } = default!;
        public string? Phone { get; set; } = default!;
        public string? Locale { get; set; } = default!;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public bool IsEmailVerified { get; set; } = false;
        public bool IsPhoneVerified { get; set; } = false;
        public UserStatus Status { get; set; } = UserStatus.Active;

        public User()
        {
            ExternalId = Guid.NewGuid();
        }
    }
}

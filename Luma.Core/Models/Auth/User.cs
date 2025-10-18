using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Globalization;

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
        public string? FirstName { get; set; } = default!;
        public string? LastName { get; set; } = default!;
        public string? MiddleName { get; set; } = default!;
        public string? Username { get; set; } = default!;
        public string? Nickname { get; set; } = default!;
        public string? ProfileUrl { get; set; } = default!;
        public string? ProfileImageUrl { get; set; } = string.Empty;
        public string? WebsiteUrl { get; set; } = default!;
        public string Email { get; set; } = default!;
        public bool IsEmailVerified { get; set; } = false;
        public string? Gender { get; set; } = default!;
        public DateOnly? Birthdate { get; set; } = default!;
        public string? ZoneInfo { get; set; } = default!;
        public string? Locale { get; set; } = default!;
        public string? Phone { get; set; } = default!;
        public bool IsPhoneVerified { get; set; } = false;
        public string? AddressJson { get; set; } = default!;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
        public UserStatus Status { get; set; } = UserStatus.Active;

        public string GetFullName()
        {
            var culture = !string.IsNullOrWhiteSpace(Locale)
                ? new CultureInfo(Locale)
                : CultureInfo.CurrentCulture;

            var familyNameFirstCultures = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "zh", 
                "ja", 
                "ko", 
                "hu", 
                "vi"  
            };

            string lang = culture.TwoLetterISOLanguageName;
            bool familyNameFirst = familyNameFirstCultures.Contains(lang);

            var givenName = FirstName?.Trim() ?? "";
            var middleNames = MiddleName?.Trim() ?? "";
            var familyName = LastName?.Trim() ?? "";

            string fullName;
            if (familyNameFirst)
            {
                fullName = string.Join(" ", new[] { familyName, givenName, middleNames }.Where(s => !string.IsNullOrEmpty(s)));
            }
            else
            {
                fullName = string.Join(" ", new[] { givenName, middleNames, familyName }.Where(s => !string.IsNullOrEmpty(s)));
            }

            return fullName;
        }

        public User()
        {
            ExternalId = Guid.NewGuid();
        }
    }
}

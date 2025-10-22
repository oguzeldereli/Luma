using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Auth
{
    public class UserLoginSession
    {
        public long Id { get; protected set; }
        public Guid ExternalId { get; protected set; }
        public long UserId { get; protected set; }
        public DateTime CreatedAtUtc { get; protected set; } = DateTime.UtcNow;
        public DateTime? ExpiresAtUtc { get; protected set; }
        public DateTime LastActivityUtc { get; set; } = DateTime.UtcNow;
        public bool IsActive { get; set; } = true;
        public string? IpAddress { get; protected set; }
        public string? UserAgent { get; protected set; }
        public string? ClientId { get; protected set; }
        public string? AuthMethod { get; protected set; }
        public string? SessionTokenHash { get; protected set; }
        public string? SessionTokenKeyId { get; protected set; }
        public string? MetadataJson { get; set; }

        public void Revoke(string? reason = null)
        {
            IsActive = false;
            ExpiresAtUtc = DateTime.UtcNow;
            MetadataJson = reason != null
                ? $"{{\"revoked_reason\":\"{reason}\",\"revoked_at\":\"{DateTime.UtcNow:o}\"}}"
                : $"{{\"revoked_at\":\"{DateTime.UtcNow:o}\"}}";
        }

        protected UserLoginSession()
        {
            ExternalId = Guid.NewGuid();
        }   

        public static UserLoginSession Create(
            long userId, 
            int validForMinutes = 1440, 
            string? ipAddress = null, 
            string? userAgent = null,
            string? clientId = null,
            string? authMethod = null,
            string? sessionTokenHash = null,
            string? sessionTokenKeyId = null,
            string? metadataJson = null)
        {
            var session = new UserLoginSession
            {
                UserId = userId,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                ClientId = clientId,
                AuthMethod = authMethod,
                SessionTokenHash = sessionTokenHash,
                SessionTokenKeyId = sessionTokenKeyId,
                MetadataJson = metadataJson,
                CreatedAtUtc = DateTime.UtcNow,
                LastActivityUtc = DateTime.UtcNow,
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(validForMinutes),
                IsActive = true
            };
            return session;
        }
    }
}
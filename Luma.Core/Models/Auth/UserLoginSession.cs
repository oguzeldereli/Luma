using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Auth
{
    public class UserLoginSession
    {
        public long Id { get; set; }
        public Guid ExternalId { get; set; }
        public long UserId { get; set; }
        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime? ExpiresAtUtc { get; set; }
        public DateTime LastActivityUtc { get; set; } = DateTime.UtcNow;
        public bool IsActive { get; set; } = true;
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public string? ClientId { get; set; }
        public string? AuthMethod { get; set; }
        public string? SessionToken { get; set; }
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
    }
}
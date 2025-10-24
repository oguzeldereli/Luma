using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Auth
{
    public class AuthorizationCode
    {
        public string Code { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public string? CodeChallenge { get; set; }
        public string? CodeChallengeMethod { get; set; }
        public string? Nonce { get; set; }
        public string Scope { get; set; } = string.Empty;
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
        public DateTimeOffset ExpiresAt { get; set; }
        public long UserId { get; set; }
        public bool Used { get; set; } = false;
    }
}

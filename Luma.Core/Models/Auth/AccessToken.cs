using Luma.Models.Auth;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Auth
{
    public class AccessToken : TokenBase
    {
        public string Scope { get; private set; } = default!;
        public string Sub { get; private set; } = default!;
        public string Aud { get; private set; } = default!;
        public string Iss { get; private set; } = default!;
        public string Jti { get; private set; } = default!;
        public bool IsRevoked { get; private set; } = false;
        public DateTime? RevokedAt { get; private set; }
        public string? RevocationReason { get; private set; }

        protected AccessToken() : base() { } 

        public static AccessToken Create(
            long userId, 
            string clientId,
            TimeSpan validFor, 
            string tokenHash, 
            string tokenHashKey, 
            string scope,
            string sub,
            string aud,
            string iss,
            string? jti = null)
        {
            return new AccessToken
            {
                UserId = userId,
                ClientId = clientId,
                ExpiresAt = DateTime.UtcNow.Add(validFor),
                TokenHash = tokenHash,
                TokenHashKeyId = tokenHashKey,
                Scope = scope,
                Sub = sub,
                Aud = aud,
                Iss = iss,
                Jti = jti ?? Guid.NewGuid().ToString()
            };
        }

        public void Revoke(string? reason = null)
        {
            if (IsRevoked)
                throw new InvalidOperationException("Refresh token is already revoked.");

            IsRevoked = true;
            RevocationReason = reason;
            RevokedAt = DateTime.UtcNow;
        }

        public bool IsActive => !IsExpired && !IsRevoked && !IsUsed;

        public override void MarkUsed()
        {
            if (IsRevoked)
                throw new InvalidOperationException("Cannot use a revoked refresh token.");
            base.MarkUsed();
        }
    }
}

using Luma.Models.Auth;
using System;

namespace Luma.Core.Models.Auth
{
    public class RefreshToken : TokenBase
    {
        public string Scope { get; private set; } = default!;
        public string Aud { get; private set; } = default!;
        public string Iss { get; private set; } = default!;
        public bool IsRevoked { get; private set; } = false;
        public DateTime? RevokedAt { get; private set; }
        public string? RevocationReason { get; private set; }

        public long AccessTokenId { get; protected set; }
        public AccessToken AccessToken { get; protected set; } = default!;

        protected RefreshToken() : base() { }

        public static RefreshToken Create(
            long userId,
            TimeSpan validFor,
            string tokenHash,
            string tokenHashKeyId,
            AccessToken accessToken)
        {
            return new RefreshToken
            {
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.Add(validFor),
                TokenHash = tokenHash,
                TokenHashKeyId = tokenHashKeyId,
                Scope = accessToken.Scope,
                Aud = accessToken.Aud,
                Iss = accessToken.Iss,
                AccessToken = accessToken,
                AccessTokenId = accessToken.Id
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

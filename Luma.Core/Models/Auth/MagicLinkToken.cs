using System.ComponentModel.DataAnnotations;

namespace Luma.Models.Auth
{
    public class MagicLinkToken : TokenBase
    {
        protected MagicLinkToken() : base()
        {

        }

        public static MagicLinkToken Create(long userId, TimeSpan validFor, string tokenHash, string tokenHashKey)
        {
            return new MagicLinkToken
            {
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.Add(validFor),
                TokenHash = tokenHash,
                TokenHashKeyId = tokenHashKey
            };
        }

        public static MagicLinkToken Create(long userId, DateTime expiresAt, string tokenHash, string tokenHashKey)
        {
            return new MagicLinkToken
            {
                UserId = userId,
                ExpiresAt = expiresAt,
                TokenHash = tokenHash,
                TokenHashKeyId = tokenHashKey
            };
        }
    }
}

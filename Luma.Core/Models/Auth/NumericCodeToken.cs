using System.ComponentModel.DataAnnotations;

namespace Luma.Models.Auth
{
    public class NumericCodeToken : TokenBase
    {
        protected NumericCodeToken() : base()
        {

        }

        public static NumericCodeToken Create(long userId, TimeSpan validFor, string tokenHash, string tokenHashKey)
        {
            return new NumericCodeToken
            {
                UserId = userId,
                ExpiresAt = DateTime.UtcNow.Add(validFor),
                TokenHash = tokenHash,
                TokenHashKeyId = tokenHashKey
            };
        }

        public static NumericCodeToken Create(long userId, DateTime expiresAt, string tokenHash, string tokenHashKey)
        {
            return new NumericCodeToken
            {
                UserId = userId,
                ExpiresAt = expiresAt,
                TokenHash = tokenHash,
                TokenHashKeyId = tokenHashKey
            };
        }
    }
}

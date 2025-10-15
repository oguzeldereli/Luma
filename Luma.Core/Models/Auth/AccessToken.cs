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

        protected AccessToken() : base() { } 

        public static AccessToken Create(
            long userId, 
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
    }
}

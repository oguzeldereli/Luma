using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Security;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Luma.Models.Auth;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Security
{
    public class IDTokenProvider : IIDTokenProvider
    {
        private readonly IUserRepository _userRepository;
        private readonly IAccessTokenRepository _accessTokenRepository;
        private readonly IJwtSigningKeyProvider _jwtSigningKeyProvider;

        public IDTokenProvider(
            IUserRepository userRepository,
            IAccessTokenRepository accessTokenRepository,
            IJwtSigningKeyProvider jwtSigningKeyProvider,
            IOptions<LumaOptions> opts)
        {
            _userRepository = userRepository;
            _accessTokenRepository = accessTokenRepository;
            _jwtSigningKeyProvider = jwtSigningKeyProvider;
        }

        public async Task<string> CreateAsync(long accessTokenId)
        {
            var accessToken = await _accessTokenRepository.GetByIdAsync(accessTokenId);
            if (accessToken is null)
                throw new ArgumentException("Access token not found.", nameof(accessTokenId));
            var user = await _userRepository.GetByIdAsync(accessToken.UserId);
            if (user is null)
                throw new ArgumentException("User not found.", nameof(accessToken.UserId));

            var claims = new List<Claim>
            {
                new("sub", user.ExternalId.ToString()),
                new("name", user.GetFullName()),
                new( "given_name", user.FirstName ?? string.Empty),
                new("family_name", user.LastName ?? string.Empty),
                new("middle_name", user.MiddleName ?? string.Empty),
                new("nickname", user.Nickname ?? string.Empty),
                new("preferred_username", user.Username ?? string.Empty),
                new("profile", user.ProfileUrl ?? string.Empty),
                new("picture", user.ProfileImageUrl ?? string.Empty),
                new("website", user.WebsiteUrl ?? string.Empty),
                new("email", user.Email),
                new("email_verified", user.IsEmailVerified.ToString().ToLowerInvariant()),
                new("gender", user.Gender ?? string.Empty),
                new("birthdate", user.Birthdate?.ToString("yyyy-MM-dd") ?? string.Empty),
                new("zoneinfo", user.ZoneInfo ?? string.Empty),
                new("locale", user.Locale ?? string.Empty),
                new("phone_number", user.Phone ?? string.Empty),
                new("phone_number_verified", user.IsPhoneVerified.ToString().ToLowerInvariant()),
                new("address", user.AddressJson ?? string.Empty),
                new("updated_at", user.UpdatedAt.ToString("yyyy-MM-dd") ?? string.Empty)
            }.Where(x => !string.IsNullOrEmpty(x.Value)).ToList();

            var creds = _jwtSigningKeyProvider.GetSigningCredentials();
            var expires = accessToken.ExpiresAt;

            var jwtToken = new JwtSecurityToken(
                issuer: accessToken.Iss,
                audience: accessToken.Aud,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            jwtToken.Header["kid"] = _jwtSigningKeyProvider.DefaultKeyId;

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(jwtToken);

            return jwt;
        }
    }
}

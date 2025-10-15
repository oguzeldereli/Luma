using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Security;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Luma.Core.Options.Tokens;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Security
{
    public sealed class JwtAccessTokenProvider : IAccessTokenProvider
    {
        private readonly IJwtSigningKeyProvider _keys;
        private readonly IAccessTokenRepository _repository;
        private readonly AccessTokenOptions _opts;

        public JwtAccessTokenProvider(
            IJwtSigningKeyProvider keys,
            IAccessTokenRepository repository,
            IOptions<LumaOptions> options)
        {
            _keys = keys;
            _repository = repository;
            _opts = options.Value.Tokens.AccessToken;
        }

        public async Task<(AccessToken token, string plain)> CreateAsync(long userId, string clientId, string? scope = null)
        {
            // Retrieve the user (for ExternalId)
            var user = await _repository.GetUserByTokenIdAsync(userId);
            if (user == null)
                throw new InvalidOperationException($"User with ID {userId} not found.");

            var sub = user.ExternalId.ToString();
            var scp = scope ?? _opts.DefaultScope;

            // Create JWT
            var creds = _keys.GetSigningCredentials();
            var now = DateTime.UtcNow;
            var expires = now.AddMinutes(_opts.ValidForMinutes);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, sub),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iss, _opts.Issuer),
                new(JwtRegisteredClaimNames.Aud, clientId),
                new("scope", scp)
            };

            var jwtToken = new JwtSecurityToken(
                issuer: _opts.Issuer,
                audience: clientId,
                claims: claims,
                notBefore: now,
                expires: expires,
                signingCredentials: creds
            );

            jwtToken.Header["kid"] = _keys.DefaultKeyId;

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(jwtToken);

            return await _repository.CreateAsync(userId, jwt);
        }

        public Task<AccessToken?> FindByRawTokenAsync(string rawToken)
        {
            // You could optionally parse JTI and check DB if you store them
            return Task.FromResult<AccessToken?>(null);
        }

        public async Task<AccessTokenValidationResult> ValidateTokenAsync(string rawToken, long userId)
        {
            var handler = new JwtSecurityTokenHandler();
            var key = _keys.GetVerificationKey(_keys.DefaultKeyId);

            var parameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _opts.Issuer,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,
                ClockSkew = TimeSpan.FromSeconds(30)
            };

            try
            {
                var principal = handler.ValidateToken(rawToken, parameters, out var validatedToken);
                var jwt = (JwtSecurityToken)validatedToken;
                var sub = principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

                // Verify subject matches the user's ExternalId
                var user = await _repository.GetUserByTokenIdAsync(userId);
                if (user == null)
                    return AccessTokenValidationResult.Invalid("User not found.");

                if (sub != user.ExternalId.ToString())
                    return AccessTokenValidationResult.Invalid("Subject mismatch.");

                // Construct token representation
                var token = AccessToken.Create(
                    userId: userId,
                    validFor: jwt.ValidTo - jwt.ValidFrom,
                    tokenHash: string.Empty,
                    tokenHashKey: _keys.DefaultKeyId,
                    scope: principal.FindFirst("scope")?.Value ?? "",
                    sub: sub ?? "",
                    aud: jwt.Audiences.FirstOrDefault() ?? "",
                    iss: jwt.Issuer
                );

                return AccessTokenValidationResult.Valid(token);
            }
            catch (Exception ex)
            {
                return AccessTokenValidationResult.Invalid(ex.Message);
            }
        }

        public async Task<AccessTokenIntrospectionResponse> IntrospectTokenAsync(string rawToken, string secret)
        {
            var handler = new JwtSecurityTokenHandler();

            if (!handler.CanReadToken(rawToken))
                return new AccessTokenIntrospectionResponse(false);

            var jwt = handler.ReadJwtToken(rawToken);
            var now = DateTime.UtcNow;

            bool active = jwt.ValidTo > now;
            var sub = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
            var aud = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Aud)?.Value;
            var scope = jwt.Claims.FirstOrDefault(c => c.Type == "scope")?.Value;

            return new AccessTokenIntrospectionResponse(
                Active: active,
                Scope: scope,
                ClientId: aud,
                UserName: null,
                Sub: sub,
                Aud: aud,
                Iss: jwt.Issuer,
                Jti: jwt.Id,
                Exp: jwt.ValidTo,
                Iat: jwt.ValidFrom,
                Nbf: jwt.Payload.NotBefore.HasValue
                    ? DateTimeOffset.FromUnixTimeSeconds(jwt.Payload.NotBefore.Value).UtcDateTime
                    : null,
                TokenType: "access_token"
            );
        }
    }
}

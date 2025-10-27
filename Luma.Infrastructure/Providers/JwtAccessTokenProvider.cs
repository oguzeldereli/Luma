using Luma.Core.DTOs.Authorization;
using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Authorization;
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

namespace Luma.Infrastructure.Providers
{
    public sealed class JwtAccessTokenProvider : IAccessTokenProvider
    {
        private readonly IJwtSigningKeyProvider _jwtSigningKeyProvider;
        private readonly IAccessTokenRepository _repository;
        private readonly AccessTokenOptions _opts;

        public JwtAccessTokenProvider(
            IJwtSigningKeyProvider jwtSigningKeyProvider,
            IAccessTokenRepository repository,
            IOptions<LumaOptions> options)
        {
            _jwtSigningKeyProvider = jwtSigningKeyProvider;
            _repository = repository;
            _opts = options.Value.Tokens.AccessToken;
        }

        public async Task<(AccessToken token, string plain)> CreateForUserAsync(long userId, string clientId, string resource, string? scope = null)
        {
            // Retrieve the user (for ExternalId)
            var user = await _repository.GetUserByTokenIdAsync(userId);
            if (user == null)
                throw new InvalidOperationException($"User with ID {userId} not found.");

            var sub = user.ExternalId.ToString();
            var scp = scope ?? _opts.DefaultScope;

            // Create JWT
            var creds = _jwtSigningKeyProvider.GetSigningCredentials();
            var now = DateTime.UtcNow;
            var expires = now.AddMinutes(_opts.ValidForMinutes);

            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, sub),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iss, _opts.Issuer),
                new(JwtRegisteredClaimNames.Aud, resource),
                new("scope", scp)
            };

            var jwtToken = new JwtSecurityToken(
                issuer: _opts.Issuer,
                audience: resource,
                claims: claims,
                notBefore: now,
                expires: expires,
                signingCredentials: creds
            );

            jwtToken.Header["kid"] = _jwtSigningKeyProvider.DefaultKeyId;

            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(jwtToken);

            return await _repository.CreateJwtAsync(clientId, jwt, userId);
        }

        public async Task<(AccessToken token, string plain)> CreateForClientAsync(string clientId, string resource, string? scope = null)
        {
            var sub = clientId;
            var scp = scope ?? _opts.DefaultScope;
            // Create JWT
            var creds = _jwtSigningKeyProvider.GetSigningCredentials();
            var now = DateTime.UtcNow;
            var expires = now.AddMinutes(_opts.ValidForMinutes);
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, sub),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Iss, _opts.Issuer),
                new(JwtRegisteredClaimNames.Aud, resource),
                new("scope", scp)
            };
            var jwtToken = new JwtSecurityToken(
                issuer: _opts.Issuer,
                audience: resource,
                claims: claims,
                notBefore: now,
                expires: expires,
                signingCredentials: creds
            );
            jwtToken.Header["kid"] = _jwtSigningKeyProvider.DefaultKeyId;
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.WriteToken(jwtToken);
            return await _repository.CreateJwtAsync(clientId, jwt);
        }

        public async Task<AccessToken?> FindByRawTokenAsync(string rawToken)
        {
            return await _repository.VerifyAsync(rawToken);
        }

        public async Task<AccessTokenValidationResult> ValidateTokenAsync(string rawToken, long userId)
        {
            var handler = new JwtSecurityTokenHandler();
            var key = _jwtSigningKeyProvider.GetVerificationKey(_jwtSigningKeyProvider.DefaultKeyId);

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

                var token = await _repository.VerifyAsync(rawToken);
                if (token == null)
                    return AccessTokenValidationResult.Invalid("Token not found in repository.");

                return AccessTokenValidationResult.Valid(token);
            }
            catch (Exception ex)
            {
                return AccessTokenValidationResult.Invalid(ex.Message);
            }
        }

        public async Task<TokenIntrospectionResponseDTO> IntrospectTokenAsync(string rawToken)
        {
            var token = await _repository.VerifyAsync(rawToken);
            if (token == null)
            {
                return new TokenIntrospectionResponseDTO(false);
            }

            var active = token != null && !token.IsExpired && !token.IsUsed;
            var user = await _repository.GetUserByTokenIdAsync(token!.Id);
            if (user == null)
            {
                return new TokenIntrospectionResponseDTO(false);
            }

            return new TokenIntrospectionResponseDTO(
                active: active,
                scope: token.Scope,
                client_id: token.ClientId,
                username: user?.Username,
                sub: token.Sub,
                aud: token.Aud,
                iss: token.Iss,
                jti: token.Jti,
                exp: token.ExpiresAt,
                iat: token.CreatedAt,
                nbf: null,
                token_type: "access_token"
            );
        }

        public async Task<bool> RevokeTokenAsync(string rawToken, string? reason = null)
        {
            var token = await _repository.VerifyAsync(rawToken);
            if (token == null || token.IsRevoked)
                return false;
            await _repository.RevokeByIdAsync(token.Id, reason);
            return true;
        }
    }
}

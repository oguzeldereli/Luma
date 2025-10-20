using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Microsoft.Extensions.Options;
using System;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Providers
{
    public sealed class OpaqueAccessTokenProvider : IAccessTokenProvider
    {
        private readonly IAccessTokenRepository _repository;

        public OpaqueAccessTokenProvider(
            IAccessTokenRepository repository,
            IOptions<LumaOptions> options)
        {
            _repository = repository;
        }

        public async Task<(AccessToken token, string plain)> CreateAsync(long userId, string clientId, string? scope = null)
            => await _repository.CreateOpaqueAsync(userId, clientId, scope);

        public Task<AccessToken?> FindByRawTokenAsync(string rawToken)
            => _repository.VerifyAsync(rawToken);

        public async Task<AccessTokenValidationResult> ValidateTokenAsync(string rawToken, long userId)
        {
            var token = await _repository.VerifyAsync(rawToken);
            if (token is null)
                return AccessTokenValidationResult.Invalid("Token not found or invalid.");

            if (token.IsExpired)
                return AccessTokenValidationResult.Invalid("Token expired.");

            if (token.IsUsed)
                return AccessTokenValidationResult.Invalid("Token already used.");

            if (token.UserId != userId)
                return AccessTokenValidationResult.Invalid("Token does not belong to the user.");

            return AccessTokenValidationResult.Valid(token);
        }

        public async Task<AccessTokenIntrospectionResponse> IntrospectTokenAsync(string rawToken, string secret)
        {
            var token = await _repository.VerifyAsync(rawToken);
            if (token is null)
                return new AccessTokenIntrospectionResponse(false);

            return new AccessTokenIntrospectionResponse(
                Active: !token.IsExpired && !token.IsUsed,
                Scope: token.Scope,
                ClientId: token.Aud,
                UserName: token.User?.Username, 
                Sub: token.Sub,
                Aud: token.Aud,
                Iss: token.Iss,
                Jti: token.Jti,
                Exp: token.ExpiresAt,
                Iat: token.CreatedAt,
                Nbf: null,
                TokenType: "access_token"
            );
        }
    }
}

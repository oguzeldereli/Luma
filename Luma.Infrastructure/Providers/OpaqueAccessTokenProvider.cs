using Luma.Core.DTOs.Authorization;
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

        public async Task<(AccessToken token, string plain)> CreateForUserAsync(long userId, string clientId, string resource, string? scope = null)
            => await _repository.CreateOpaqueAsync(clientId, resource, userId, scope);

        public async Task<(AccessToken token, string plain)> CreateForClientAsync(string clientId, string resource, string? scope = null)
            => await _repository.CreateOpaqueAsync(clientId, resource, scope: scope);

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
            if (token == null || token.IsExpired || token.IsUsed)
            {
                return false;
            }
            await _repository.RevokeByIdAsync(token.Id, reason);
            return true;
        }
    }
}

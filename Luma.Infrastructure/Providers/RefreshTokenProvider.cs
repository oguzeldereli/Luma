using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Providers
{
    public class RefreshTokenProvider : IRefreshTokenProvider
    {
        private readonly IRefreshTokenRepository _refreshTokenRepository;
        private readonly IAccessTokenRepository _accessTokenRepository;

        public RefreshTokenProvider(
            IRefreshTokenRepository refreshTokenRepository,
            IAccessTokenRepository accessTokenRepository,
            IOptions<LumaOptions> options)
        {
            _refreshTokenRepository = refreshTokenRepository;
            _accessTokenRepository = accessTokenRepository;
        }

        public async Task<(RefreshToken token, string plain)> CreateAsync(long accessTokenId)
        {
            var token = await _accessTokenRepository.GetByIdAsync(accessTokenId);
            if (token == null)
            {
                throw new InvalidOperationException($"Access token with ID {accessTokenId} not found.");
            }

            return await _refreshTokenRepository.CreateAsync(token.UserId, accessTokenId);
        }

        public async Task<RefreshToken?> FindByRawTokenAsync(string rawToken)
        {
            return await _refreshTokenRepository.FindByRawTokenAsync(rawToken);
        }

        public async Task<RefreshTokenValidationResult> ValidateAndUseTokenAsync(string rawToken, string clientId)
        {
            var token = await _refreshTokenRepository.VerifyAsync(rawToken);

            if (token is null)
                return RefreshTokenValidationResult.Invalid("Token not found or invalid.");

            var accessToken = await _accessTokenRepository.GetByIdAsync(token.AccessTokenId);
            if (accessToken is null)
                return RefreshTokenValidationResult.Invalid("Associated access token not found.");

            if (token.Aud != clientId)
                return RefreshTokenValidationResult.Invalid("Token audience does not match client ID.");

            if (token.IsExpired)
                return RefreshTokenValidationResult.Invalid("Token is expired.");

            if (token.IsRevoked)
                return RefreshTokenValidationResult.Invalid("Token has been revoked.");

            if (token.IsUsed)
                return RefreshTokenValidationResult.Invalid("Token has already been used.");

            await _refreshTokenRepository.MarkUsedByIdAsync(token.Id);
            return RefreshTokenValidationResult.Valid(token);
        }
    }
}

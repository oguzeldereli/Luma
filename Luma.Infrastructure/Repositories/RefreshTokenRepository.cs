using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Security;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Luma.Infrastructure.Data;
using Luma.Infrastructure.Security;
using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Repositories
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly TokenGenerator _tokenGenerator;
        private readonly TokenHasher _tokenHasher;
        private readonly IHmacKeyProvider _tokenHashKeyProvider;
        private readonly IOptions<LumaOptions> _options;

        public RefreshTokenRepository(
            ApplicationDbContext context,
            TokenGenerator tokenGenerator,
            TokenHasher tokenHasher,
            IHmacKeyProvider tokenHashKeyProvider,
            IOptions<LumaOptions> options)
        {
            _context = context;
            _tokenGenerator = tokenGenerator;
            _tokenHasher = tokenHasher;
            _tokenHashKeyProvider = tokenHashKeyProvider;
            _options = options;
        }

        public async Task<(RefreshToken token, string plain)> CreateAsync(long userId, long accessTokenId)
        {
            var tokenOpts = _options.Value.Tokens.RefreshToken;
            var validForDays = tokenOpts.ValidForDays;
            if (validForDays is < 7 or > 90)
                throw new ArgumentOutOfRangeException(nameof(validForDays), "Refresh tokens must be valid between 7 and 90 days.");

            var keyId = _tokenHashKeyProvider.DefaultKeyId;
            var validFor = TimeSpan.FromDays(validForDays);

            var accessToken = await _context.AccessTokens.FindAsync(accessTokenId);
            if (accessToken == null)
                throw new ArgumentException("Access token does not exist.", nameof(accessTokenId));

            (string plain, string hash, string hashKeyId) = _tokenGenerator.GenerateOpaqueToken(64, keyId);

            var token = RefreshToken.Create(
                userId: userId,
                clientId: accessToken.ClientId,
                accessToken: accessToken,
                validFor: validFor,
                tokenHash: hash,
                tokenHashKeyId: hashKeyId
            );

            _context.RefreshTokens.Add(token);
            await _context.SaveChangesAsync();

            return (token, plain);
        }

        public async Task<RefreshToken?> FindByRawTokenAsync(string rawToken)
        {
            var defaultKeyId = _tokenHashKeyProvider.DefaultKeyId;
            var hash = _tokenHasher.ComputeHashForLookup(rawToken, defaultKeyId);

            var token = await _context.RefreshTokens
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.TokenHash == hash && t.TokenHashKeyId == defaultKeyId);

            if (token != null && token.IsActive)
                return token;

            foreach (var keyId in _tokenHashKeyProvider.AllKeyIds)
            {
                var altHash = _tokenHasher.ComputeHashForLookup(rawToken, keyId);
                var found = await _context.RefreshTokens
                    .Include(t => t.User)
                    .FirstOrDefaultAsync(t => t.TokenHash == altHash && t.TokenHashKeyId == keyId);

                if (found != null && found.IsActive)
                    return found;
            }

            return null;
        }

        public async Task<RefreshTokenValidationResult> ValidateTokenAsync(string rawToken, long userId)
        {
            var token = await FindByRawTokenAsync(rawToken);
            if (token == null)
                return RefreshTokenValidationResult.Invalid("Token not found or invalid.");

            if (token.UserId != userId)
                return RefreshTokenValidationResult.Invalid("Token does not belong to this user.");

            if (token.IsExpired)
                return RefreshTokenValidationResult.Invalid("Token is expired.");

            if (token.IsRevoked)
                return RefreshTokenValidationResult.Invalid("Token has been revoked.");

            if (token.IsUsed)
                return RefreshTokenValidationResult.Invalid("Token has already been used.");

            return RefreshTokenValidationResult.Valid(token);
        }

        public async Task<RefreshToken?> GetByIdAsync(long id)
            => await _context.RefreshTokens.FindAsync(id);

        public async Task<RefreshToken?> GetByExternalIdAsync(Guid externalId)
            => await _context.RefreshTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);

        public async Task<RefreshToken?> GetByHashAsync(string tokenHash)
            => await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

        public async Task<long?> GetPrimaryIdFromExternalIdAsync(Guid externalId)
            => await _context.RefreshTokens
                .Where(t => t.ExternalId == externalId)
                .Select(t => (long?)t.Id)
                .FirstOrDefaultAsync();

        public async Task<Guid?> GetExternalIdFromPrimaryIdAsync(long id)
            => await _context.RefreshTokens
                .Where(t => t.Id == id)
                .Select(t => (Guid?)t.ExternalId)
                .FirstOrDefaultAsync();

        public async Task<bool> ExistsByHashAsync(string tokenHash)
            => await _context.RefreshTokens.AnyAsync(t => t.TokenHash == tokenHash);

        public async Task<bool> MarkUsedByIdAsync(long id)
        {
            var token = await _context.RefreshTokens.FindAsync(id);
            if (token == null) return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByExternalIdAsync(Guid externalId)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null) return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByHashAsync(string tokenHash)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByIdAsync(long id)
        {
            var token = await _context.RefreshTokens.FindAsync(id);
            if (token == null) return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByExternalIdAsync(Guid externalId)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null) return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByHashAsync(string tokenHash)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByIdAsync(long id)
        {
            var token = await _context.RefreshTokens.FindAsync(id);
            if (token == null) return false;
            _context.RefreshTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByExternalIdAsync(Guid externalId)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null) return false;
            _context.RefreshTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByHashAsync(string tokenHash)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            _context.RefreshTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<int> DeleteExpiredAsync(long? userId = null)
        {
            var now = DateTime.UtcNow;
            var query = _context.RefreshTokens.Where(t => t.ExpiresAt <= now);
            if (userId.HasValue)
                query = query.Where(t => t.UserId == userId);
            var expired = await query.ToListAsync();
            _context.RefreshTokens.RemoveRange(expired);
            return await _context.SaveChangesAsync();
        }

        public async Task<int> DeleteAllAsync()
        {
            _context.RefreshTokens.RemoveRange(_context.RefreshTokens);
            return await _context.SaveChangesAsync();
        }

        public async Task<RefreshToken?> VerifyAsync(string plainToken)
        {
            var defaultKeyId = _tokenHashKeyProvider.DefaultKeyId;
            var defaultHash = _tokenHasher.ComputeHashForLookup(plainToken, defaultKeyId);
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == defaultHash && t.TokenHashKeyId == defaultKeyId);

            if (token != null && token.IsActive)
                return token;

            foreach (var keyId in _tokenHashKeyProvider.AllKeyIds)
            {
                var hash = _tokenHasher.ComputeHashForLookup(plainToken, keyId);
                var found = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == hash && t.TokenHashKeyId == keyId);
                if (found != null && found.IsActive)
                    return found;
            }

            return null;
        }


        public async Task<bool> RevokeByIdAsync(long tokenId, string? reason = null)
        {
            var token = await _context.RefreshTokens.FindAsync(tokenId);
            if (token == null) return false;
            token.Revoke(reason);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> RevokeByExternalIdAsync(Guid tokenId, string? reason = null)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.ExternalId == tokenId);
            if (token == null) return false;
            token.Revoke(reason);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> RevokeByHashAsync(string tokenHash, string? reason = null)
        {
            var token = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            token.Revoke(reason);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}

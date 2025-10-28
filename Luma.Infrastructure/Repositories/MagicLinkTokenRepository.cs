using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Data;
using Luma.Infrastructure.Security;
using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Repositories
{
    public class MagicLinkTokenRepository : IMagicLinkTokenRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ITokenHasher _tokenHasher;
        private readonly IHmacKeyProvider _tokenHashKeyProvider;
        private readonly IOptions<LumaOptions> _options;

        public MagicLinkTokenRepository(
            ApplicationDbContext context, 
            ITokenGenerator tokenGenerator,
            ITokenHasher tokenHasher,
            IHmacKeyProvider tokenHashKeyProvider,
            IOptions<LumaOptions> options)
        {
            _context = context;
            _tokenGenerator = tokenGenerator;
            _tokenHasher = tokenHasher;
            _tokenHashKeyProvider = tokenHashKeyProvider;
            _options = options;
        }

        public async Task<(MagicLinkToken token, string plain)> CreateAsync(long userId)
        {
            int validForMinutes = _options.Value.Tokens.MagicLinkToken.ValidForMinutes;
            int tokenLength = _options.Value.Tokens.MagicLinkToken.CodeLength;
            string keyId = _tokenHashKeyProvider.DefaultKeyId;

            if (!(await _context.Users.AnyAsync(u => u.Id == userId)))
                throw new ArgumentException("User does not exist.", nameof(userId));

            if (validForMinutes > 20)
                throw new ArgumentOutOfRangeException(nameof(_options.Value.Tokens.MagicLinkToken.ValidForMinutes), "Magic link tokens cannot be valid for more than 20 minutes.");

            (string plain, string hash, string key) = _tokenGenerator.GenerateOpaqueToken(tokenLength, keyId);
            var token = MagicLinkToken.Create(userId, TimeSpan.FromMinutes(validForMinutes), hash, key);
            _context.MagicLinkTokens.Add(token);
            await _context.SaveChangesAsync();
            return (token, plain);
        }

        public async Task<int> DeleteAllAsync()
        {
            var tokens = _context.MagicLinkTokens;
            _context.MagicLinkTokens.RemoveRange(tokens);
            return await _context.SaveChangesAsync();
        }

        public async Task<bool> DeleteByExternalIdAsync(Guid externalId)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null)
                return false;
            _context.MagicLinkTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByHashAsync(string tokenHash)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null)
                return false;
            _context.MagicLinkTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByIdAsync(long id)
        {
            var token = await _context.MagicLinkTokens.FindAsync(id);
            if (token == null)
                return false;
            _context.MagicLinkTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<int> DeleteExpiredAsync(long? userId = null)
        {
            var now = DateTime.UtcNow;
            var tokens = _context.MagicLinkTokens.Where(t => t.ExpiresAt <= now);
            if (userId.HasValue)
            {
                tokens = tokens.Where(t => t.UserId == userId.Value);
            }
            var tokensToDelete = await tokens.ToListAsync();
            _context.MagicLinkTokens.RemoveRange(tokensToDelete);
            return await _context.SaveChangesAsync();
        }

        public async Task<bool> ExistsByHashAsync(string tokenHash)
        {
            return await _context.MagicLinkTokens.AsNoTracking().AnyAsync(t => t.TokenHash == tokenHash);
        }

        public async Task<bool> ExpireByExternalIdAsync(Guid externalId)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null)
                return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByHashAsync(string tokenHash)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null)
                return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByIdAsync(long id)
        {
            var token = await _context.MagicLinkTokens.FindAsync(id);
            if (token == null)
                return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<MagicLinkToken?> GetByExternalIdAsync(Guid externalId)
        {
            return await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
        }

        public async Task<MagicLinkToken?> GetByHashAsync(string tokenHash)
        {
            return await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
        }

        public async Task<MagicLinkToken?> GetByIdAsync(long id)
        {
            return await _context.MagicLinkTokens.FindAsync(id);
        }

        public async Task<Guid?> GetExternalIdFromPrimaryIdAsync(long id)
        {
            var token = await _context.MagicLinkTokens.FindAsync(id);
            return token?.ExternalId;
        }

        public async Task<long?> GetPrimaryIdFromExternalIdAsync(Guid externalId)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            return token?.Id;
        }

        public async Task<bool> MarkUsedByExternalIdAsync(Guid externalId)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null)
                return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByHashAsync(string tokenHash)
        {
            var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null)
                return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByIdAsync(long id)
        {
            var token = await _context.MagicLinkTokens.FindAsync(id);
            if (token == null)
                return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<MagicLinkToken?> VerifyAsync(string plainToken)
        {
            // try default key first
            var defaultKeyId = _tokenHashKeyProvider.DefaultKeyId;
            var defaultHash = _tokenHasher.ComputeHashForLookup(plainToken, defaultKeyId);
            var defaultToken = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.TokenHash == defaultHash && t.TokenHashKeyId == defaultKeyId);
            if (defaultToken != null && !defaultToken.IsExpired && !defaultToken.IsUsed)
            {
                return defaultToken;
            }

            // try everything if not found
            var keys = _tokenHashKeyProvider.AllKeyIds.ToList();
            foreach (var keyId in keys)
            {
                var hash = _tokenHasher.ComputeHashForLookup(plainToken, keyId);
                var token = await _context.MagicLinkTokens.FirstOrDefaultAsync(t => t.TokenHash == hash && t.TokenHashKeyId == keyId);
                if (token != null && !token.IsExpired && !token.IsUsed)
                {
                    return token;
                }
            }
            return null;
        }
    }
}

using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Data;
using Luma.Infrastructure.Security;
using Luma.Models.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Luma.Infrastructure.Repositories
{
    public class NumericCodeTokenRepository : INumericCodeTokenRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly ITokenGenerator _tokenGenerator;
        private readonly ITokenHasher _tokenHasher;
        private readonly IHmacKeyProvider _tokenHashKeyProvider;
        private readonly IOptions<LumaOptions> _options;

        public NumericCodeTokenRepository(
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

        public async Task<(NumericCodeToken token, string plain)> CreateAsync(long userId)
        {
            int validForMinutes = _options.Value.Tokens.NumericCodeToken.ValidForMinutes;
            int digits = _options.Value.Tokens.NumericCodeToken.DigitCount;
            string keyId = _tokenHashKeyProvider.DefaultKeyId;

            if (!(await _context.Users.AnyAsync(u => u.Id == userId)))
                throw new ArgumentException("User does not exist.", nameof(userId));

            if (validForMinutes > 20)
                throw new ArgumentOutOfRangeException(nameof(_options.Value.Tokens.NumericCodeToken.ValidForMinutes), "Numeric code tokens cannot be valid for more than 20 minutes.");

            (string plain, string hash, string key) = _tokenGenerator.GenerateNumericCode(digits, keyId);
            var token = NumericCodeToken.Create(userId, TimeSpan.FromMinutes(validForMinutes), hash, key);
            _context.NumericCodeTokens.Add(token);
            await _context.SaveChangesAsync();
            return (token, plain);
        }

        public async Task<int> DeleteAllAsync()
        {
            var tokens = _context.NumericCodeTokens;
            _context.NumericCodeTokens.RemoveRange(tokens);
            return await _context.SaveChangesAsync();
        }

        public async Task<bool> DeleteByExternalIdAsync(Guid externalId)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null)
                return false;
            _context.NumericCodeTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByHashAsync(string tokenHash)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null)
                return false;
            _context.NumericCodeTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByIdAsync(long id)
        {
            var token = await _context.NumericCodeTokens.FindAsync(id);
            if (token == null)
                return false;
            _context.NumericCodeTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<int> DeleteExpiredAsync(long? userId = null)
        {
            var now = DateTime.UtcNow;
            var tokens = _context.NumericCodeTokens.Where(t => t.ExpiresAt <= now);
            if (userId.HasValue)
            {
                tokens = tokens.Where(t => t.UserId == userId.Value);
            }
            var tokensToDelete = await tokens.ToListAsync();
            _context.NumericCodeTokens.RemoveRange(tokensToDelete);
            return await _context.SaveChangesAsync();
        }

        public async Task<bool> ExistsByHashAsync(string tokenHash)
        {
            return await _context.NumericCodeTokens.AsNoTracking().AnyAsync(t => t.TokenHash == tokenHash);
        }

        public async Task<bool> ExpireByExternalIdAsync(Guid externalId)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null)
                return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByHashAsync(string tokenHash)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null)
                return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByIdAsync(long id)
        {
            var token = await _context.NumericCodeTokens.FindAsync(id);
            if (token == null)
                return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<NumericCodeToken?> GetByExternalIdAsync(Guid externalId)
        {
            return await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
        }

        public async Task<NumericCodeToken?> GetByHashAsync(string tokenHash)
        {
            return await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
        }

        public async Task<NumericCodeToken?> GetByIdAsync(long id)
        {
            return await _context.NumericCodeTokens.FindAsync(id);
        }

        public async Task<Guid?> GetExternalIdFromPrimaryIdAsync(long id)
        {
            var token = await _context.NumericCodeTokens.FindAsync(id);
            return token?.ExternalId;
        }

        public async Task<long?> GetPrimaryIdFromExternalIdAsync(Guid externalId)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            return token?.Id;
        }

        public async Task<bool> MarkUsedByExternalIdAsync(Guid externalId)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null)
                return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByHashAsync(string tokenHash)
        {
            var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null)
                return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByIdAsync(long id)
        {
            var token = await _context.NumericCodeTokens.FindAsync(id);
            if (token == null)
                return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<NumericCodeToken?> VerifyAsync(string plainToken)
        {
            // Try default key first
            var defaultKeyId = _tokenHashKeyProvider.DefaultKeyId;
            var defaultHash = _tokenHasher.ComputeHashForLookup(plainToken, defaultKeyId);
            var defaultToken = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.TokenHash == defaultHash && t.TokenHashKeyId == defaultKeyId);
            if (defaultToken != null && !defaultToken.IsExpired && !defaultToken.IsUsed)
            {
                return defaultToken;
            }

            // Fallback: try all known keys
            var keys = _tokenHashKeyProvider.AllKeyIds.ToList();
            foreach (var keyId in keys)
            {
                var hash = _tokenHasher.ComputeHashForLookup(plainToken, keyId);
                var token = await _context.NumericCodeTokens.FirstOrDefaultAsync(t => t.TokenHash == hash && t.TokenHashKeyId == keyId);
                if (token != null && !token.IsExpired && !token.IsUsed)
                {
                    return token;
                }
            }
            return null;
        }
    }
}

using Luma.Core.Interfaces.Auth;
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
    public class AccessTokenRepository : IAccessTokenRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly TokenGenerator _tokenGenerator;
        private readonly TokenHasher _tokenHasher;
        private readonly IHmacKeyProvider _tokenHashKeyProvider;
        private readonly IOptions<LumaOptions> _options;

        public AccessTokenRepository(
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

        public async Task<(AccessToken token, string plain)> CreateOpaqueAsync(long userId, string clientId, string? scope = null)
        {
            var tokenOpts = _options.Value.Tokens.AccessToken;
            var validForMinutes = tokenOpts.ValidForMinutes;
            if (validForMinutes is < 10 or > 30)
                throw new ArgumentOutOfRangeException(nameof(validForMinutes), "Access tokens must be valid between 10 and 30 minutes.");

            var keyId = _tokenHashKeyProvider.DefaultKeyId;
            var keyBytes = _tokenHashKeyProvider.GetKey(keyId);
            var validFor = TimeSpan.FromMinutes(validForMinutes);

            // Generate opaque token (random)
            (string plain, string hash, string hashKeyId) = _tokenGenerator.GenerateOpaqueToken(64, keyId);

            var userExternalId = await _context.Users
                .AsNoTracking()
                .Where(u => u.Id == userId)
                .Select(u => u.ExternalId)
                .FirstOrDefaultAsync();

            // Construct token model
            var token = AccessToken.Create(
                userId: userId,
                validFor: validFor,
                tokenHash: hash,
                tokenHashKey: hashKeyId,
                scope: scope ?? tokenOpts.DefaultScope,
                sub: userId.ToString(),
                aud: clientId,
                iss: tokenOpts.Issuer
            );

            _context.AccessTokens.Add(token);
            await _context.SaveChangesAsync();
            return (token, plain);
        }

        public async Task<(AccessToken token, string plain)> CreateJwtAsync(long userId, string jwt)
        {
            var defaultKeyId = _tokenHashKeyProvider.DefaultKeyId;
            var tokenOpts = _options.Value.Tokens.AccessToken;
            var validForMinutes = tokenOpts.ValidForMinutes;
            if (validForMinutes is < 10 or > 30)
                throw new ArgumentOutOfRangeException(nameof(validForMinutes), "Access tokens must be valid between 10 and 30 minutes.");

            // extract sub, aud, and iss from jwt
            var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(jwt);
            
            var userExternalId = await _context.Users
                .AsNoTracking()
                .Where(u => u.Id == userId)
                .Select(u => new { u.ExternalId })
                .FirstOrDefaultAsync();
            if (userExternalId == null)
                throw new ArgumentException("User not found.", nameof(userId));

            var sub = jwtToken.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub)?.Value;
            if (sub == null)
            {
                sub = userExternalId.ExternalId.ToString();
            }
            else
            {
                if (userExternalId.ExternalId.ToString() != sub)
                    throw new ArgumentException("The 'sub' claim in the JWT does not match the user's external ID.");
            }

            var aud = jwtToken.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Aud)?.Value ?? "unknown";
            var iss = jwtToken.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Iss)?.Value ?? tokenOpts.Issuer;
            var jti = jwtToken.Claims.FirstOrDefault(c => c.Type == System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti)?.Value ?? Guid.NewGuid().ToString();
            var scope = jwtToken.Claims.FirstOrDefault(c => c.Type == "scope")?.Value ?? tokenOpts.DefaultScope;
            
            var (plain, hash, hashKeyId) = _tokenGenerator.GenerateJwtTokenHash(jwt, defaultKeyId);

            AccessToken token = AccessToken.Create(
                userId: userId,
                validFor: TimeSpan.FromMinutes(validForMinutes),
                tokenHash: hash,
                tokenHashKey: hashKeyId,
                scope: scope,
                sub: sub,
                aud: aud,
                iss: iss,
                jti: jti
            );

            _context.AccessTokens.Add(token);
            await _context.SaveChangesAsync();
            return (token, plain);
        }

        public async Task<User?> GetUserByTokenIdAsync(long tokenId)
        {
            var token = await _context.AccessTokens
                .AsNoTracking()
                .Include(t => t.User)
                .FirstOrDefaultAsync(t => t.Id == tokenId);
            return token?.User;
        }

        public async Task<int> DeleteAllAsync()
        {
            _context.AccessTokens.RemoveRange(_context.AccessTokens);
            return await _context.SaveChangesAsync();
        }

        public async Task<bool> DeleteByExternalIdAsync(Guid externalId)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null) return false;
            _context.AccessTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByHashAsync(string tokenHash)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            _context.AccessTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteByIdAsync(long id)
        {
            var token = await _context.AccessTokens.FindAsync(id);
            if (token == null) return false;
            _context.AccessTokens.Remove(token);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<int> DeleteExpiredAsync(long? userId = null)
        {
            var now = DateTime.UtcNow;
            var query = _context.AccessTokens.Where(t => t.ExpiresAt <= now);
            if (userId.HasValue)
                query = query.Where(t => t.UserId == userId);
            var expired = await query.ToListAsync();
            _context.AccessTokens.RemoveRange(expired);
            return await _context.SaveChangesAsync();
        }

        public async Task<bool> ExistsByHashAsync(string tokenHash)
            => await _context.AccessTokens.AsNoTracking().AnyAsync(t => t.TokenHash == tokenHash);

        public async Task<bool> ExpireByExternalIdAsync(Guid externalId)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null) return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByHashAsync(string tokenHash)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ExpireByIdAsync(long id)
        {
            var token = await _context.AccessTokens.FindAsync(id);
            if (token == null) return false;
            token.ExpireNow();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<AccessToken?> GetByExternalIdAsync(Guid externalId)
            => await _context.AccessTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);

        public async Task<AccessToken?> GetByHashAsync(string tokenHash)
            => await _context.AccessTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);

        public async Task<AccessToken?> GetByIdAsync(long id)
            => await _context.AccessTokens.FindAsync(id);

        public async Task<Guid?> GetExternalIdFromPrimaryIdAsync(long id)
        {
            var token = await _context.AccessTokens.FindAsync(id);
            return token?.ExternalId;
        }

        public async Task<long?> GetPrimaryIdFromExternalIdAsync(Guid externalId)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            return token?.Id;
        }

        public async Task<bool> MarkUsedByExternalIdAsync(Guid externalId)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.ExternalId == externalId);
            if (token == null) return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByHashAsync(string tokenHash)
        {
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.TokenHash == tokenHash);
            if (token == null) return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> MarkUsedByIdAsync(long id)
        {
            var token = await _context.AccessTokens.FindAsync(id);
            if (token == null) return false;
            token.MarkUsed();
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<AccessToken?> VerifyAsync(string plainToken)
        {
            // Try with default key
            var defaultKeyId = _tokenHashKeyProvider.DefaultKeyId;
            var defaultHash = _tokenHasher.ComputeHashForLookup(plainToken, defaultKeyId);
            var token = await _context.AccessTokens.FirstOrDefaultAsync(t => t.TokenHash == defaultHash && t.TokenHashKeyId == defaultKeyId);

            if (token != null && !token.IsExpired && !token.IsUsed)
                return token;

            // Try all keys (in case of rotation)
            foreach (var keyId in _tokenHashKeyProvider.AllKeyIds)
            {
                var hash = _tokenHasher.ComputeHashForLookup(plainToken, keyId);
                var found = await _context.AccessTokens.FirstOrDefaultAsync(t => t.TokenHash == hash && t.TokenHashKeyId == keyId);
                if (found != null && !found.IsExpired && !found.IsUsed)
                    return found;
            }

            return null;
        }

        async Task<(AccessToken token, string plain)> ITokenRepository<AccessToken>.CreateAsync(long userId)
            => await CreateOpaqueAsync(userId, clientId: "unknown");
    }
}

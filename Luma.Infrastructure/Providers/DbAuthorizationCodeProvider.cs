using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Auth;
using Luma.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Luma.Infrastructure.Providers
{
    /// <summary>
    /// Database-backed store for issued authorization codes, shared across all instances. Redemption
    /// uses an atomic delete so a code can only be exchanged once even under concurrent requests
    /// hitting different instances.
    /// </summary>
    public class DbAuthorizationCodeProvider : IAuthorizationCodeProvider
    {
        private readonly ApplicationDbContext _context;

        public DbAuthorizationCodeProvider(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<bool> SaveAsync(string code, AuthorizationCode entry, int expiresIn = 120)
        {
            if (string.IsNullOrEmpty(code) || entry == null)
                return false;

            entry.Code = code;
            _context.AuthorizationCodes.Add(entry);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<AuthorizationCode?> GetAsync(string code)
        {
            if (string.IsNullOrEmpty(code))
                return null;

            var entity = await _context.AuthorizationCodes
                .AsNoTracking()
                .FirstOrDefaultAsync(c => c.Code == code);

            if (entity == null)
                return null;

            if (entity.Used || entity.ExpiresAt <= DateTime.UtcNow)
            {
                await _context.AuthorizationCodes.Where(c => c.Code == code).ExecuteDeleteAsync();
                return null;
            }

            return entity;
        }

        public async Task<bool> DeleteAsync(string code)
        {
            if (string.IsNullOrEmpty(code))
                return false;

            // Atomic single-use claim: only the request that actually removes the row "wins".
            var affected = await _context.AuthorizationCodes
                .Where(c => c.Code == code)
                .ExecuteDeleteAsync();

            return affected > 0;
        }
    }
}

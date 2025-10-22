using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Security;
using Luma.Core.Models.Auth;
using Luma.Infrastructure.Data;
using Luma.Infrastructure.Security;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Repositories
{
    public class UserLoginSessionRepository : IUserLoginSessionRepository
    {
        private readonly ApplicationDbContext _context;
        private readonly TokenHasher _tokenHasher;
        private readonly IHmacKeyProvider _keyProvider;

        public UserLoginSessionRepository(
            ApplicationDbContext context,
            TokenHasher tokenHasher,
            IHmacKeyProvider keyProvider)
        {
            _context = context;
            _tokenHasher = tokenHasher;
            _keyProvider = keyProvider;
        }

        public async Task<UserLoginSession?> GetByIdAsync(long id)
        {
            return await _context.UserLoginSessions.FindAsync(id);
        }

        public async Task<UserLoginSession?> GetByExternalIdAsync(Guid externalId)
        {
            return await _context.UserLoginSessions
                .FirstOrDefaultAsync(s => s.ExternalId == externalId);
        }

        public async Task<UserLoginSession?> GetBySessionTokenAsync(string sessionToken)
        {
            // try with default key first
            var defaultKeyId = _keyProvider.DefaultKeyId;
            var defaultHash = _tokenHasher.ComputeHashForLookup(sessionToken, defaultKeyId);
            var session = await _context.UserLoginSessions
                .FirstOrDefaultAsync(s => s.SessionTokenHash == defaultHash && s.SessionTokenKeyId == defaultKeyId);
            if (session != null)
                return session;

            // try all keys to find a match
            var allKeys = _keyProvider.AllKeyIds;
            foreach (var keyId in allKeys)
            {
                var hash = _tokenHasher.ComputeHashForLookup(sessionToken, keyId);
                var found = await _context.UserLoginSessions
                    .FirstOrDefaultAsync(s => s.SessionTokenHash == hash && s.SessionTokenKeyId == keyId);

                if (found != null && found.ExpiresAtUtc <= DateTime.UtcNow && found.IsActive)
                    return found;
            }

            return null;
        }

        public async Task<List<UserLoginSession>> GetActiveSessionsByUserIdAsync(long userId)
        {
            return await _context.UserLoginSessions
                .Where(s => s.UserId == userId && s.IsActive)
                .OrderByDescending(s => s.LastActivityUtc)
                .ToListAsync();
        }

        public async Task<UserLoginSession> CreateAsync(UserLoginSession session)
        {
            session.LastActivityUtc = DateTime.UtcNow;

            _context.UserLoginSessions.Add(session);
            await _context.SaveChangesAsync();
            return session;
        }

        public async Task<UserLoginSession> UpdateAsync(UserLoginSession session)
        {
            session.LastActivityUtc = DateTime.UtcNow;
            _context.UserLoginSessions.Update(session);
            await _context.SaveChangesAsync();
            return session;
        }

        public async Task<bool> RevokeAsync(long id, string? reason = null)
        {
            var session = await _context.UserLoginSessions.FindAsync(id);
            if (session == null)
                return false;

            session.Revoke(reason);
            _context.UserLoginSessions.Update(session);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> DeleteAsync(long id)
        {
            var session = await _context.UserLoginSessions.FindAsync(id);
            if (session == null)
                return false;

            _context.UserLoginSessions.Remove(session);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<int> CountAsync()
        {
            return await _context.UserLoginSessions.CountAsync();
        }

        public async Task<List<UserLoginSession>> GetAllAsync(int skip = 0, int take = 100)
        {
            return await _context.UserLoginSessions
                .OrderByDescending(s => s.CreatedAtUtc)
                .Skip(skip)
                .Take(take)
                .ToListAsync();
        }
    }
}

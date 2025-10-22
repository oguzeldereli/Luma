using Luma.Core.Interfaces.Authentication;
using Luma.Core.Models.Auth;
using Luma.Infrastructure.Data;
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

        public UserLoginSessionRepository(ApplicationDbContext context)
        {
            _context = context;
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
            return await _context.UserLoginSessions
                .FirstOrDefaultAsync(s => s.SessionToken == sessionToken && s.IsActive);
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
            session.CreatedAtUtc = DateTime.UtcNow;
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

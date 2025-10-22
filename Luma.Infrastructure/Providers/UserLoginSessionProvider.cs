using Luma.Core.Interfaces.Authentication;
using Luma.Core.Models.Auth;
using Luma.Infrastructure.Repositories;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Providers
{
    public class UserLoginSessionProvider : IUserLoginSessionProvider
    {
        private readonly IUserLoginSessionRepository _repository;

        public UserLoginSessionProvider(IUserLoginSessionRepository repository)
        {
            _repository = repository;
        }

        public async Task<UserLoginSession?> GetBySessionTokenAsync(string sessionToken)
        {
            if (string.IsNullOrWhiteSpace(sessionToken))
                return null;

            var session = await _repository.GetBySessionTokenAsync(sessionToken);

            if (session == null)
                return null;

            // check expiration and activity
            if (session.ExpiresAtUtc.HasValue && session.ExpiresAtUtc.Value <= DateTime.UtcNow)
            {
                await _repository.RevokeAsync(session.Id, "Session expired");
                return null;
            }

            return session;
        }

        public async Task<UserLoginSession?> GetByExternalIdAsync(Guid externalId)
        {
            return await _repository.GetByExternalIdAsync(externalId);
        }

        public async Task<List<UserLoginSession>> GetActiveSessionsByUserIdAsync(long userId)
        {
            return await _repository.GetActiveSessionsByUserIdAsync(userId);
        }

        public async Task<UserLoginSession> CreateAsync(UserLoginSession session, int expiresInSeconds = 28800)
        {
            if (session == null)
                throw new ArgumentNullException(nameof(session));

            session.CreatedAtUtc = DateTime.UtcNow;
            session.LastActivityUtc = DateTime.UtcNow;
            session.ExpiresAtUtc = DateTime.UtcNow.AddSeconds(expiresInSeconds);
            session.IsActive = true;

            return await _repository.CreateAsync(session);
        }

        public async Task<bool> RefreshActivityAsync(long sessionId)
        {
            var session = await _repository.GetByIdAsync(sessionId);
            if (session == null || !session.IsActive)
                return false;

            session.LastActivityUtc = DateTime.UtcNow;
            await _repository.UpdateAsync(session);
            return true;
        }

        public async Task<bool> RevokeAsync(long sessionId, string? reason = null)
        {
            return await _repository.RevokeAsync(sessionId, reason);
        }

        public async Task<bool> DeleteAsync(long sessionId)
        {
            return await _repository.DeleteAsync(sessionId);
        }
    }
}

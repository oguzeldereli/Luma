using Luma.Core.Interfaces.Authentication;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Luma.Infrastructure.Repositories;
using Luma.Infrastructure.Security;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Providers
{
    public class UserLoginSessionProvider : IUserLoginSessionProvider
    {
        private readonly IUserRepository _userRepository;
        private readonly IUserLoginSessionRepository _repository;
        private readonly TokenGenerator _generator;
        private readonly IOptions<LumaOptions> _options;

        public UserLoginSessionProvider(
            IUserRepository userRepository,
            IUserLoginSessionRepository repository,
            TokenGenerator generator,
            IOptions<LumaOptions> options)
        {
            _userRepository = userRepository;
            _repository = repository;
            _generator = generator;
            _options = options;
        }

        public async Task<UserLoginSession?> GetBySessionTokenAsync(string sessionToken)
        {
            if (string.IsNullOrWhiteSpace(sessionToken))
                return null;

            var session = await _repository.GetBySessionTokenAsync(sessionToken);

            if (session == null)
                return null;

            // check expiration and activity
            if (session.ExpiresAtUtc is { } expiresAt && expiresAt <= DateTime.UtcNow)
            {
                await _repository.RevokeAsync(session.Id, "Session expired");
                return null;
            }

            if (session.IsActive == false)
                return null;

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

        public async Task<(string plain, UserLoginSession session)> CreateAsync(
            long userId, 
            string? ipAddress = null,
            string? userAgent = null,
            string? clientId = null,
            string? authMethod = null,
            string? metadataJson = null)
        {
            var userExists = await _userRepository.GetByIdAsync(userId) == null ? false : true;
            if (!userExists)
                throw new ArgumentException("User does not exist", nameof(userId));

            var validFor = _options.Value.AuthenticationServer.UserLoginSessionsValidForMinutes;
            if (validFor is < 60 or > 10080)
                validFor = 1440; // default to 1 day if out of range

            var (plain, hashed, keyId) = _generator.GenerateOpaqueToken(32);
            UserLoginSession session = UserLoginSession.Create(
                userId: userId,
                validForMinutes: validFor,
                ipAddress: ipAddress,
                userAgent: userAgent,
                clientId: clientId,
                authMethod: authMethod,
                sessionTokenHash: hashed,
                sessionTokenKeyId: keyId,
                metadataJson: metadataJson
            );

            session.LastActivityUtc = DateTime.UtcNow;
            session.IsActive = true;

            return (plain, await _repository.CreateAsync(session));
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

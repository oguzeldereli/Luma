using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Services;
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Providers
{
    public class InMemoryAuthorizationCodeStateProvider : IAuthorizationCodeStateProvider
    {
        private class StoredState
        {
            public AuthorizationCodeStateDTO Data { get; init; } = default!;
            public DateTimeOffset ExpiresAt { get; init; }
        }

        private readonly ConcurrentDictionary<string, StoredState> _store = new();
        private readonly Timer _cleanupTimer;

        public InMemoryAuthorizationCodeStateProvider()
        {
            _cleanupTimer = new Timer(_ => CleanupExpired(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        public Task<OAuthServiceResponse<bool>> SaveAsync(string state, AuthorizationCodeStateDTO codeState, int expiresIn = 600)
        {
            if (string.IsNullOrEmpty(state))
                return Task.FromResult(OAuthServiceResponse<bool>.Failure("invalid_request", "State cannot be null or empty.", ""));

            if (codeState == null)
                return Task.FromResult(OAuthServiceResponse<bool>.Failure("invalid_request", "AuthorizationCodeStateDTO cannot be null.", state));

            var entry = new StoredState
            {
                Data = codeState,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
            };

            _store[state] = entry;
            return Task.FromResult(OAuthServiceResponse<bool>.Success(true, state));
        }

        public Task<OAuthServiceResponse<AuthorizationCodeStateDTO>> GetAsync(string state)
        {
            if (string.IsNullOrEmpty(state))
                return Task.FromResult(OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "State is required.", ""));

            if (_store.TryGetValue(state, out var entry))
            {
                if (DateTimeOffset.UtcNow <= entry.ExpiresAt)
                    return Task.FromResult(OAuthServiceResponse<AuthorizationCodeStateDTO>.Success(entry.Data, state));

                // Expired → remove
                _store.TryRemove(state, out _);
                return Task.FromResult(OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "Authorization code state expired.", state));
            }

            return Task.FromResult(OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "Authorization code state not found.", state));
        }

        public Task<OAuthServiceResponse<bool>> DeleteAsync(string state)
        {
            if (string.IsNullOrEmpty(state))
                return Task.FromResult(OAuthServiceResponse<bool>.Failure("invalid_request", "State is required.", state));

            var removed = _store.TryRemove(state, out _);
            return Task.FromResult(OAuthServiceResponse<bool>.Success(removed, state));
        }

        private void CleanupExpired()
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kvp in _store)
            {
                if (kvp.Value.ExpiresAt <= now)
                    _store.TryRemove(kvp.Key, out _);
            }
        }
    }
}

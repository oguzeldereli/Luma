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

        public async Task<bool> SaveAsync(string id, AuthorizationCodeStateDTO codeState, int expiresIn = 600)
        {
            if (string.IsNullOrEmpty(id))
                return false;

            if (codeState == null)
                return false;

            var entry = new StoredState
            {
                Data = codeState,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
            };

            _store[id] = entry;
            return true;
        }

        public async Task<AuthorizationCodeStateDTO?> GetAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;

            if (_store.TryGetValue(id, out var entry))
            {
                if (DateTimeOffset.UtcNow <= entry.ExpiresAt)
                    return entry.Data;

                _store.TryRemove(id, out _);
                return null;
            }

            return null;
        }

        public async Task<bool> DeleteAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return false;

            var removed = _store.TryRemove(id, out _);
            return removed;
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

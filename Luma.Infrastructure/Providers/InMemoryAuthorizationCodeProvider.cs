using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Models.Services;
using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Providers
{
    public class InMemoryAuthorizationCodeProvider : IAuthorizationCodeProvider
    {
        private class StoredCode
        {
            public AuthorizationCode Data { get; init; } = default!;
            public DateTimeOffset ExpiresAt { get; init; }
        }

        private readonly ConcurrentDictionary<string, StoredCode> _store = new();
        private readonly Timer _cleanupTimer;

        public InMemoryAuthorizationCodeProvider()
        {
            // Periodically purge expired codes every minute
            _cleanupTimer = new Timer(_ => CleanupExpired(), null, TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
        }

        public async Task<bool> SaveAsync(string code, AuthorizationCode entry, int expiresIn = 120)
        {
            if (string.IsNullOrEmpty(code))
                return false;
            if (entry == null)
                return false;

            var stored = new StoredCode
            {
                Data = entry,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
            };

            _store[code] = stored;
            return true;
        }

        public async Task<AuthorizationCode?> GetAsync(string code)
        {
            if (string.IsNullOrEmpty(code))
                return null;

            if (_store.TryGetValue(code, out var stored))
            {
                if (DateTimeOffset.UtcNow <= stored.ExpiresAt && !stored.Data.Used)
                {
                    return stored.Data;
                }

                _store.TryRemove(code, out _);
                return null;
            }

            return null;
        }

        public async Task<bool> DeleteAsync(string code)
        {
            if (string.IsNullOrEmpty(code))
                return false;

            var removed = _store.TryRemove(code, out _);
            return removed;
        }

        private void CleanupExpired()
        {
            var now = DateTimeOffset.UtcNow;
            foreach (var kvp in _store)
            {
                if (kvp.Value.ExpiresAt <= now || kvp.Value.Data.Used)
                    _store.TryRemove(kvp.Key, out _);
            }
        }
    }
}

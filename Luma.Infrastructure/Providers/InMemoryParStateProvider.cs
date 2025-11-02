using Luma.Core.Interfaces.Authorization;
using System.Collections.Concurrent;

namespace Luma.Infrastructure.Authorization
{
    public class InMemoryParStateProvider : IParStateProvider
    {
        private static readonly ConcurrentDictionary<string, string> _store
            = new ConcurrentDictionary<string, string>();

        public Task<string?> StoreParStateAsync(string state)
        {
            var externalId = Guid.NewGuid().ToString("N");

            _store[externalId] = state;
            return Task.FromResult<string?>(externalId);
        }

        public Task<string?> RetrieveParStateAsync(string externalId)
        {
            return Task.FromResult(
                _store.TryGetValue(externalId, out var state)
                    ? state
                    : null
            );
        }

        public Task<bool> RemoveParStateByStateAsync(string state)
        {
            var match = _store
                .FirstOrDefault(kvp => kvp.Value == state);

            if (match.Key is null)
                return Task.FromResult(false);

            return Task.FromResult(_store.TryRemove(match.Key, out _));
        }

        public Task<bool> RemoveParStateByExternalIdAsync(string externalId)
        {
            return Task.FromResult(
                _store.TryRemove(externalId, out _)
            );
        }
    }
}

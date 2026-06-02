using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Auth;
using Luma.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.Json;

namespace Luma.Infrastructure.Providers
{
    /// <summary>
    /// Database-backed store for in-progress authorization state, shared across all instances.
    /// Replaces the previous single-instance in-memory store.
    /// </summary>
    public class DbAuthorizationCodeStateProvider : IAuthorizationCodeStateProvider
    {
        private readonly ApplicationDbContext _context;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        public DbAuthorizationCodeStateProvider(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<bool> SaveAsync(string id, AuthorizationCodeStateDTO codeState, int expiresIn = 600)
        {
            if (string.IsNullOrEmpty(id) || codeState == null)
                return false;

            var json = JsonSerializer.Serialize(codeState, JsonOptions);
            var expiresAt = DateTime.UtcNow.AddSeconds(expiresIn);

            var existing = await _context.AuthorizationCodeStates.FindAsync(id);
            if (existing == null)
            {
                _context.AuthorizationCodeStates.Add(new AuthorizationCodeState
                {
                    Id = id,
                    ClientId = codeState.clientId,
                    DataJson = json,
                    ExpiresAtUtc = expiresAt
                });
            }
            else
            {
                existing.ClientId = codeState.clientId;
                existing.DataJson = json;
                existing.ExpiresAtUtc = expiresAt;
            }

            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<AuthorizationCodeStateDTO?> GetAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return null;

            var entity = await _context.AuthorizationCodeStates
                .AsNoTracking()
                .FirstOrDefaultAsync(s => s.Id == id);

            if (entity == null)
                return null;

            if (entity.ExpiresAtUtc <= DateTime.UtcNow)
            {
                await _context.AuthorizationCodeStates.Where(s => s.Id == id).ExecuteDeleteAsync();
                return null;
            }

            return JsonSerializer.Deserialize<AuthorizationCodeStateDTO>(entity.DataJson, JsonOptions);
        }

        public async Task<bool> DeleteAsync(string id)
        {
            if (string.IsNullOrEmpty(id))
                return false;

            var affected = await _context.AuthorizationCodeStates
                .Where(s => s.Id == id)
                .ExecuteDeleteAsync();

            return affected > 0;
        }
    }
}

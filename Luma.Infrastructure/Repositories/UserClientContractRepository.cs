using Luma.Core.Interfaces.Authentication;
using Luma.Core.Models.Auth;
using Luma.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;

namespace Luma.Infrastructure.Repositories
{
    public class UserClientContractRepository : IUserClientContractRepository
    {
        private readonly ApplicationDbContext _context;

        public UserClientContractRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<UserClientContract?> GetAsync(long userId, string clientId)
        {
            return await _context.UserClientContracts
                .FirstOrDefaultAsync(c => c.UserId == userId && c.ClientId == clientId);
        }

        public async Task<List<UserClientContract>> GetByUserAsync(long userId)
        {
            return await _context.UserClientContracts
                .Where(c => c.UserId == userId)
                .ToListAsync();
        }

        public async Task<bool> HasConsentForScopesAsync(long userId, string clientId, IEnumerable<string> scopes)
        {
            var contract = await GetAsync(userId, clientId);
            if (contract == null || !contract.Consented)
                return false;

            var granted = contract.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return scopes.All(s => granted.Contains(s));
        }

        public async Task<UserClientContract> GrantConsentAsync(long userId, string clientId, string scope)
        {
            var requested = scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var contract = await GetAsync(userId, clientId);

            if (contract == null)
            {
                contract = UserClientContract.Create(userId, clientId, consented: true, scope: string.Join(' ', requested));
                _context.UserClientContracts.Add(contract);
            }
            else
            {
                var merged = contract.Scope
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Union(requested)
                    .ToArray();

                contract.Scope = string.Join(' ', merged);
                contract.Consented = true;
                contract.UpdatedAt = DateTime.UtcNow;
                _context.UserClientContracts.Update(contract);
            }

            await _context.SaveChangesAsync();
            return contract;
        }

        public async Task<bool> RevokeAsync(long userId, string clientId)
        {
            var contract = await GetAsync(userId, clientId);
            if (contract == null)
                return false;

            _context.UserClientContracts.Remove(contract);
            await _context.SaveChangesAsync();
            return true;
        }
    }
}

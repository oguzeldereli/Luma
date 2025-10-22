using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authentication
{
    public interface IUserLoginSessionRepository
    {
        Task<UserLoginSession?> GetByIdAsync(long id);
        Task<UserLoginSession?> GetByExternalIdAsync(Guid externalId);
        Task<UserLoginSession?> GetBySessionTokenAsync(string sessionToken);
        Task<List<UserLoginSession>> GetActiveSessionsByUserIdAsync(long userId);
        Task<UserLoginSession> CreateAsync(UserLoginSession session);
        Task<UserLoginSession> UpdateAsync(UserLoginSession session);
        Task<bool> RevokeAsync(long id, string? reason = null);
        Task<bool> DeleteAsync(long id);
        Task<int> CountAsync();
        Task<List<UserLoginSession>> GetAllAsync(int skip = 0, int take = 100);
    }
}

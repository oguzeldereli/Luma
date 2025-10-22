using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authentication
{
    public interface IUserLoginSessionProvider
    {
        Task<UserLoginSession?> GetBySessionTokenAsync(string sessionToken);
        Task<UserLoginSession?> GetByExternalIdAsync(Guid externalId);
        Task<List<UserLoginSession>> GetActiveSessionsByUserIdAsync(long userId);
        Task<UserLoginSession> CreateAsync(UserLoginSession session, int expiresInSeconds = 28800); // default 8 hours
        Task<bool> RefreshActivityAsync(long sessionId);
        Task<bool> RevokeAsync(long sessionId, string? reason = null);
        Task<bool> DeleteAsync(long sessionId);
    }
}

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
        Task<(string plain, UserLoginSession session)> CreateAsync(
            long userId,
            string? ipAddress = null,
            string? userAgemt = null,
            string? clientId = null,
            string? authMethod = null,
            string? metadataJson = null);
        Task<bool> RefreshActivityAsync(long sessionId);
        Task<bool> RevokeAsync(long sessionId, string? reason = null);
        Task<bool> DeleteAsync(long sessionId);
    }
}

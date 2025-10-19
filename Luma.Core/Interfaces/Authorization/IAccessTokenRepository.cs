using Luma.Core.Interfaces.Shared;
using Luma.Core.Models.Auth;
using Luma.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IAccessTokenRepository : ITokenRepository<AccessToken>
    {
        Task<(AccessToken token, string plain)> CreateOpaqueAsync(long userId, string clientId, string? scope = null);
        Task<(AccessToken token, string plain)> CreateJwtAsync(long userId, string jwt);
        Task<User?> GetUserByTokenIdAsync(long tokenId);

        Task<bool> RevokeByIdAsync(long tokenId, string? reason = null);
        Task<bool> RevokeByExternalIdAsync(Guid tokenId, string? reason = null);
        Task<bool> RevokeByHashAsync(string tokenHash, string? reason = null);
    }
}

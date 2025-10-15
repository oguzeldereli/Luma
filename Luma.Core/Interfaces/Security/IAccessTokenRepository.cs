using Luma.Core.Interfaces.Auth;
using Luma.Core.Models.Auth;
using Luma.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Security
{
    public interface IAccessTokenRepository : ITokenRepository<AccessToken>
    {
        Task<(AccessToken token, string plain)> CreateAsync(long userId, string clientId, string? scope = null);
        Task<(AccessToken token, string plain)> CreateAsync(string jwt);
        Task<User?> GetUserByTokenIdAsync(long tokenId);
    }
}

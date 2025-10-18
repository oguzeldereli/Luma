using Luma.Core.DTOs.Security;
using Luma.Core.Interfaces.Auth;
using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Security
{
    internal interface IRefreshTokenRepository : ITokenRepository<RefreshToken>
    {
        Task<(RefreshToken token, string plain)> CreateAsync(long userId, long accessTokenId);
        Task<RefreshToken?> FindByRawTokenAsync(string rawToken);
        Task<RefreshTokenValidationResult> ValidateTokenAsync(string rawToken, long userId);
    }
}

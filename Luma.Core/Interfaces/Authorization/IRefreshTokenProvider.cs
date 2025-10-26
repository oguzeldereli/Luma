using Luma.Core.DTOs.Authorization;
using Luma.Core.DTOs.Security;
using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IRefreshTokenProvider
    {
        Task<(RefreshToken token, string plain)> CreateAsync(long accessTokenId);
        Task<RefreshToken?> FindByRawTokenAsync(string rawToken);
        Task<RefreshTokenValidationResult> ValidateAndUseTokenAsync(string rawToken, string clientId);
        Task<TokenIntrospectionResponseDTO> IntrospectTokenAsync(string rawToken);
    }
}

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
    public interface IAccessTokenProvider
    {
        Task<(AccessToken token, string plain)> CreateForUserAsync(long userId, string clientId, string resource, string? scope = null);
        Task<(AccessToken token, string plain)> CreateForClientAsync(string clientId, string resource, string? scope = null);

        Task<AccessToken?> FindByRawTokenAsync(string rawToken);
        Task<AccessTokenValidationResult> ValidateTokenAsync(string rawToken, long userId);
        Task<TokenIntrospectionResponseDTO> IntrospectTokenAsync(string rawToken);
    }
}

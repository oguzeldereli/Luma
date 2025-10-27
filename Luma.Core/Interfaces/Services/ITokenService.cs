using Luma.Core.DTOs.Authorization;
using Luma.Core.Models.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Services
{
    public interface ITokenService
    {
        Task<OAuthServiceResponse<TokenResponseDTO>> IssueTokensFromAuthorizationCode(TokenRequestDTO request);
        Task<OAuthServiceResponse<TokenResponseDTO>> IssueTokensFromRefreshToken(TokenRefreshDTO request);
        Task<OAuthServiceResponse<TokenResponseDTO>> IssueTokensFromClientCredentials(TokenClientCredentialsDTO request);
        Task<OAuthServiceResponse<TokenIntrospectionResponseDTO>> IntrospectToken(TokenIntrospectionRequestDTO request);
        Task<OAuthServiceResponse<bool>> RevokeToken(TokenRevocationRequestDTO request);
    }
}

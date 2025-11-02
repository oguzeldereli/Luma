using Luma.Core.DTOs.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Models.Services;
using Luma.Models.Auth;
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
        Task<ServiceResponse<UserInfoResponseDTO?>> GetUserInfoAsync(string rawAccessToken);
        Task<OAuthServiceResponse<TokenIntrospectionResponseDTO>> IntrospectToken(TokenIntrospectionRequestDTO request);
        Task<OAuthServiceResponse<bool>> RevokeToken(TokenRevocationRequestDTO request);
        Task<ServiceResponse<List<JsonWebKeySetEntry>>> GetJWKS();
    }
}

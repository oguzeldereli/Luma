using Luma.Core.DTOs.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Models.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Services
{
    public interface IAuthorizeService
    {
        Task<OAuthServiceResponse<string>> CreateAuthorizationCodeStateAsync(AuthorizeRequestDTO request);
        Task<ServiceResponse<AuthorizationCodeStateDTO>> GetAuthorizationCodeStateAsync(string clientId, string state);
        Task<ServiceResponse<bool>> DeleteAuthorizationCodeStateAsync(string clientId, string state);
        Task<OAuthServiceResponse<string>> GenerateAuthorizationCodeAsync(long userId, string state);
        Task<OAuthServiceResponse<AuthorizationCode>> ValidateAndUseAuthorizationCodeAsync(string code, string clientId);
        Task<bool> VerifyPkceCodeVerifierAsync(string codeVerifier, string codeChallenge, string codeChallengeMethod);
    }
}

using Luma.Core.DTOs.Authorization;
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
        Task<OAuthServiceResponse<AuthorizationCodeStateDTO>> StartAuthorizationAsync(AuthorizeRequestDTO request);
        Task<OAuthServiceResponse<(string clientId, string state)>> SaveAuthorizationCodeStateAsync(AuthorizationCodeStateDTO codeState);
        Task<OAuthServiceResponse<AuthorizationCodeStateDTO>> GetAuthorizationCodeStateAsync(string clientId, string state);
        Task<OAuthServiceResponse<bool>> DeleteAuthorizationCodeStateAsync(string clientId, string state);
        Task<OAuthServiceResponse<string>> GenerateAuthorizationCodeAsync(AuthorizationCodeStateDTO codeState);
        Task<OAuthServiceResponse<bool>> ValidateAuthorizationCodeAsync(string code, string clientId);
    }
}

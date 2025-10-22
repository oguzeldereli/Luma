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
        Task<(bool redirectSafe, OAuthServiceResponse<string>)> CreateAuthorizationCodeStateAsync(AuthorizeRequestDTO request);
        Task<ServiceResponse<AuthorizationCodeStateDTO>> GetAuthorizationCodeStateAsync(string clientId, string state);
        Task<ServiceResponse<bool>> DeleteAuthorizationCodeStateAsync(string clientId, string state);
        Task<OAuthServiceResponse<string>> GenerateAuthorizationCodeAsync(string state);
        Task<OAuthServiceResponse<bool>> ValidateAndUseAuthorizationCodeAsync(string code, string clientId);
    }
}

using Luma.Core.DTOs.Authorization;
using Luma.Core.Models.Services;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IAuthorizationCodeStateProvider
    {
        Task<OAuthServiceResponse<bool>> SaveAsync(string state, AuthorizationCodeStateDTO codeState, int expiresIn = 600);
        Task<OAuthServiceResponse<AuthorizationCodeStateDTO>> GetAsync(string state);
        Task<OAuthServiceResponse<bool>> DeleteAsync(string state);
    }
}

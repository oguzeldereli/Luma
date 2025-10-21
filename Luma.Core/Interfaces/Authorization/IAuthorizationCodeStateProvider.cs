using Luma.Core.DTOs.Authorization;
using Luma.Core.Models.Services;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IAuthorizationCodeStateProvider
    {
        Task<bool> SaveAsync(string state, AuthorizationCodeStateDTO codeState, int expiresIn = 600);
        Task<AuthorizationCodeStateDTO?> GetAsync(string state);
        Task<bool> DeleteAsync(string state);
    }
}

using Luma.Core.DTOs.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Models.Services;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IAuthorizationCodeProvider
    {
        Task<bool> SaveAsync(string code, AuthorizationCode entry, int expiresIn = 120);

        Task<AuthorizationCode> GetAsync(string code);

        Task<bool> DeleteAsync(string code);
    }
}

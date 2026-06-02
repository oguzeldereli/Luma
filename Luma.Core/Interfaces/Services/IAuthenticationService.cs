using Luma.Core.Models.Services;
using Luma.Models.Auth;

namespace Luma.Core.Interfaces.Services
{
    public interface IAuthenticationService
    {
        Task<User?> FindUserByEmailAsync(string email);

        Task<ServiceResponse<User>> RegisterUserAsync(string email, string? firstName, string? lastName);

        /// <summary>Generates a numeric code for the user and emails it.</summary>
        Task<ServiceResponse<bool>> SendNumericCodeAsync(User user);

        /// <summary>
        /// Generates a magic-link token for the user and emails it. The link is built by the caller
        /// from the generated plain token via <paramref name="magicLinkUrlBuilder"/>.
        /// </summary>
        Task<ServiceResponse<bool>> SendMagicLinkAsync(User user, Func<string, string> magicLinkUrlBuilder);

        /// <summary>Verifies a numeric code and returns the owning user id.</summary>
        Task<ServiceResponse<long>> VerifyNumericCodeAsync(string code);

        /// <summary>Verifies a magic-link token and returns the owning user id.</summary>
        Task<ServiceResponse<long>> VerifyMagicLinkAsync(string token);

        Task<bool> HasValidConsentAsync(long userId, string clientId, IEnumerable<string> scopes);

        Task GrantConsentAsync(long userId, string clientId, string scope);
    }
}

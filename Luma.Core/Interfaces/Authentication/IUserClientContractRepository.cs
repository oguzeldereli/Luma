using Luma.Core.Models.Auth;

namespace Luma.Core.Interfaces.Authentication
{
    public interface IUserClientContractRepository
    {
        Task<UserClientContract?> GetAsync(long userId, string clientId);
        Task<List<UserClientContract>> GetByUserAsync(long userId);

        /// <summary>
        /// Returns true when the user has an active consent for the client that already covers every
        /// requested scope.
        /// </summary>
        Task<bool> HasConsentForScopesAsync(long userId, string clientId, IEnumerable<string> scopes);

        /// <summary>
        /// Creates or updates the consent record for (user, client), storing the union of any
        /// previously granted scopes and the newly granted ones.
        /// </summary>
        Task<UserClientContract> GrantConsentAsync(long userId, string clientId, string scope);

        Task<bool> RevokeAsync(long userId, string clientId);
    }
}

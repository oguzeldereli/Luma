using Luma.Models.Auth;

namespace Luma.Core.Interfaces.Shared
{
    public interface ITokenRepository<T> where T : TokenBase
    {
        // Read
        Task<long?> GetPrimaryIdFromExternalIdAsync(Guid externalId);
        Task<Guid?> GetExternalIdFromPrimaryIdAsync(long id);
        Task<T?> GetByIdAsync(long id);
        Task<T?> GetByExternalIdAsync(Guid externalId);
        Task<T?> GetByHashAsync(string tokenHash);
        Task<T?> VerifyAsync(string plainToken);
        Task<bool> ExistsByHashAsync(string tokenHash);

        // Update
        Task<bool> MarkUsedByIdAsync(long id);
        Task<bool> MarkUsedByExternalIdAsync(Guid externalId);
        Task<bool> MarkUsedByHashAsync(string tokenHash);
        Task<bool> ExpireByIdAsync(long id);
        Task<bool> ExpireByExternalIdAsync(Guid externalId);
        Task<bool> ExpireByHashAsync(string tokenHash);

        // Delete
        Task<bool> DeleteByIdAsync(long id);
        Task<bool> DeleteByExternalIdAsync(Guid externalId);
        Task<bool> DeleteByHashAsync(string tokenHash);
        Task<int> DeleteExpiredAsync(long? userId = null);
        Task<int> DeleteAllAsync();
    }
}

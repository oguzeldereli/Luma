using Luma.Models.Auth;

namespace Luma.Core.Models.Auth
{
    /// <summary>
    /// Records that a user has consented to a client accessing a given set of scopes. Clients are
    /// configuration-defined and therefore identified by their string client_id (there is no Client
    /// table to reference).
    /// </summary>
    public class UserClientContract
    {
        public long Id { get; set; }
        public Guid ExternalId { get; set; }

        public string ClientId { get; set; } = string.Empty;
        public long UserId { get; set; }
        public bool Consented { get; set; }
        public string Scope { get; set; } = string.Empty;

        public User User { get; set; } = null!;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

        protected UserClientContract()
        {
            ExternalId = Guid.NewGuid();
        }

        public static UserClientContract Create(
            long userId,
            string clientId,
            bool consented,
            string scope)
        {
            return new UserClientContract
            {
                UserId = userId,
                ClientId = clientId,
                Consented = consented,
                Scope = scope
            };
        }
    }
}

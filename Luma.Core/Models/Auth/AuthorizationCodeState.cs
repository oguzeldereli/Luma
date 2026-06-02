namespace Luma.Core.Models.Auth
{
    /// <summary>
    /// Persistent backing record for an in-progress authorization request (the state created at
    /// <c>/authorize</c> and consumed once a user authenticates). Stored in the shared database so it
    /// is available across all server instances. The full <c>AuthorizationCodeStateDTO</c> is kept as
    /// JSON in <see cref="DataJson"/>.
    /// </summary>
    public class AuthorizationCodeState
    {
        /// <summary>The state id (the value carried in the state-id cookie).</summary>
        public string Id { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string DataJson { get; set; } = string.Empty;
        public DateTime ExpiresAtUtc { get; set; }
    }
}

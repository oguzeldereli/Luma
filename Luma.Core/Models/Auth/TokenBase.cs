using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Luma.Models.Auth
{
    public abstract class TokenBase
    {
        public long Id { get; set; }
        public Guid ExternalId { get; private set; }
        public string TokenHash { get; protected set; } = default!;
        public string TokenHashKeyId { get; protected set; } = default!;
        public DateTime CreatedAt { get; private set; } = DateTime.UtcNow;
        public DateTime ExpiresAt { get; protected set; }
        public bool IsUsed { get; protected set; } = false;
        public DateTime? UsedAt { get; protected set; }

        public long UserId { get; protected set; }
        public User User { get; protected set; } = default!;

        public bool IsExpired => DateTime.UtcNow > ExpiresAt;

        protected TokenBase()
        {
            ExternalId = Guid.NewGuid();
        }

        public virtual void MarkUsed()
        {
            if (IsExpired || IsUsed)
                throw new InvalidOperationException("Token cannot be reused or is expired.");
            IsUsed = true;
            UsedAt = DateTime.UtcNow;
        }

        public virtual void ExpireNow()
        {
            if (IsUsed)
                throw new InvalidOperationException("Token already used.");
            if (!IsExpired)
                ExpiresAt = DateTime.UtcNow;
        }

        public override string ToString() =>
            $"{GetType().Name}[Id={Id}, UserId={UserId}, ExpiresAt={ExpiresAt:u}, IsUsed={IsUsed}]";
    }
}

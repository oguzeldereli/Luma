using Luma.Core.Models.Auth;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Security
{
    public interface IJwtSigningKeyProvider
    {
        string Algorithm { get; }
        string DefaultKeyId { get; }
        IEnumerable<string> AllKeyIds { get; }

        bool HasKey(string keyId);

        SecurityKey GetSigningKey(string keyId);
        SigningCredentials GetSigningCredentials(string? keyId = null);
        SecurityKey GetVerificationKey(string keyId);
        List<JsonWebKeySetEntry> GetJsonWebKeySet();
    }
}

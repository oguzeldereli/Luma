using Luma.Core.Options.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options
{
    public class OAuthOptions
    {
        // Note: configuration binding appends to pre-populated lists, which would duplicate entries.
        // Keep this empty so the configured Luma:OAuth:SupportedScopes fully controls the value.
        public List<string> SupportedScopes { get; set; } = new();
        public List<ClientConfig> Clients { get; set; } = new();
        public AuthorizationCodeOptions AuthorizationCode { get; set; } = new();
        public int ParExpirationSeconds { get; set; } = 90;
    }
}

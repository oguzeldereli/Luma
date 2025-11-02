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
        public List<string> SupportedScopes { get; set; } = new()
        {
            "openid",
            "profile",
            "email",
            "address",
            "phone"
        };
        public List<ClientConfig> Clients { get; set; } = new();
        public AuthorizationCodeOptions AuthorizationCode { get; set; } = new();
        public int ParExpirationSeconds { get; set; } = 90;
    }
}

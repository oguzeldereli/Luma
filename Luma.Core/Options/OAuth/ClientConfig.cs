using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.OAuth
{
    public class ClientConfig
    {
        public string ClientId { get; set; } = default!;
        public string DefaultPostLogoutRedirectUri { get; set; } = default!;
        public List<string> PostLogoutRedirectUris { get; set; } = new();
        public string DefaultResource { get; set; } = default!;
        public List<string> Resources { get; set; } = default!;
        public string ClientSecretSHA256_Base64 { get; set; } = default!;
        public string DisplayName { get; set; } = default!;
        public string DefaultRedirectUri { get; set; } = default!;
        public List<string> RedirectUris { get; set; } = new();
        public List<string> AllowedGrantTypes { get; set; } = new();
        public string DefaultScope { get; set; } = "openid profile email";
        public List<string> AllowedScopes { get; set; } = new();
        public bool IsConfidential { get; set; } = false;
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Auth
{
    public class Client
    {
        public string ClientId { get; set; } = default!;
        public string ClientSecretSHA256_Base64 { get; set; } = default!;
        public string DisplayName { get; set; } = default!;
        public List<string> RedirectUris { get; set; } = new();
        public List<string> AllowedGrantTypes { get; set; } = new();
        public List<string> AllowedScopes { get; set; } = new();
        public bool IsConfidential { get; set; } = false;
    }
}

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
        public string ClientSecret { get; set; } = default!;
        public string DisplayName { get; set; } = default!;
        public List<string> AllowedGrantTypes { get; set; } = new();
        public List<string> AllowedScopes { get; set; } = new();
        public bool IsConfidential { get; set; } = false;
    }
}

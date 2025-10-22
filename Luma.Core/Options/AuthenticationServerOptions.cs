using Luma.Core.Options.AuthenticationServer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options
{
    public class AuthenticationServerOptions
    {
        public int UserSessionsValidForMinutes { get; set; } = 1440;
        public bool UseAuthentication { get; set; }
        public bool UseCustomFiles { get; set; }
        public CustomFilesOptions CustomFiles { get; set; } = new();
    }
}

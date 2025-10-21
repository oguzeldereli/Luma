using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.OAuth
{
    public class AuthorizationCodeOptions
    {
        public int ValidForSeconds { get; set; } = 90;
    }
}

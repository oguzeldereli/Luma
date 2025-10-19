using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options.AuthenticationServer
{
    public class CustomFilesOptions
    {
        public string ViewMode { get; set; } = "Razor";
        public string Path { get; set; } = "./wwwroot";
    }
}

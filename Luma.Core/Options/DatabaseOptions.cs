using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Options
{
    public class DatabaseOptions
    {
        public string Provider { get; set; } = "Sqlite";
        public string ConnectionString { get; set; } = string.Empty;
    }
}

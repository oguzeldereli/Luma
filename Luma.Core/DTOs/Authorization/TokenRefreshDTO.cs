using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenRefreshDTO(
        string grant_type,
        string refresh_token,
        string client_id,
        string client_secret,
        string? scope = null);
}

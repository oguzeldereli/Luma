using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenResponseDTO(
        string access_token,
        string token_type,
        int expires_in,
        string refresh_token,
        string scope,
        string id_token)
    {
    }
}

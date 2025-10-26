using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{

    public record TokenRevocationRequestDTO(
        string token,
        string client_id,
        string client_secret,
        string? token_type_hint = null
        );
}

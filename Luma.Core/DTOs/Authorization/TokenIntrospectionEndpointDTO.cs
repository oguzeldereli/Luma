using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenIntrospectionEndpointDTO(
        string token,
        string? client_id = null,
        string? client_secret = null,
        string? token_type_hint = null
        );
}

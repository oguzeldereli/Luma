using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenIntrospectionResponseDTO(
        bool active,
        string? scope = null,
        string? client_id = null,
        string? username = null,
        string? token_type = "access_token",
        DateTime? exp = null,
        DateTime? iat = null,
        DateTime? nbf = null,
        string? sub = null,
        string? aud = null,
        string? iss = null,
        string? jti = null);
}

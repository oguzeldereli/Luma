using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Security
{
    public record AccessTokenIntrospectionResponse(
        bool Active,
        string? Scope = null,
        string? ClientId = null,
        string? UserName = null,
        string? Sub = null,
        string? Aud = null,
        string? Iss = null,
        string? Jti = null,
        DateTime? Exp = null,
        DateTime? Iat = null,
        DateTime? Nbf = null,
        string? TokenType = "access_token");
}

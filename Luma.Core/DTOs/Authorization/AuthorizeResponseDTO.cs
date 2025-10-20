using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record AuthorizeResponseDTO(
        string code,
        string? state = null);

    public record AuthorizeResponseTokenDTO(
        string AccessToken,
        string TokenType,
        int ExpiresIn,
        string? RefreshToken = null,
        string? IdToken = null,
        string? Scope = null);
}

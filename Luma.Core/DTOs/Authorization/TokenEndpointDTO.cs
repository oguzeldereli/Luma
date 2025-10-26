using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenEndpointDTO(
        string grant_type,
        string? code = null,
        string? redirect_uri = null,
        string? client_id = null,
        string? client_secret = null,
        string? code_verifier = null,
        string? refresh_token = null,
        string? resource = null,
        string? scope = null);
}

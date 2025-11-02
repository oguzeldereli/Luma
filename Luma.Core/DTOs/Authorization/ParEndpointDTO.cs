using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record ParEndpointDTO
        (string client_id,
        string? response_type,
        string? client_secret,
        string? redirect_uri,
        string? scope,
        string? state,
        string? resource = null,
        string? code_challenge = null,
        string? code_challenge_method = "S256",
        string? nonce = null,
        string? response_mode = "query",
        string? prompt = null,
        int? max_age = null,
        string? login_hint = null,
        string? claims = null);
}

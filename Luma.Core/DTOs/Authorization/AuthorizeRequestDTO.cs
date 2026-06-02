using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record AuthorizeRequestDTO
        (string client_id,
        string? response_type,
        string? redirect_uri, 
        string? scope, 
        string? state,
        string? resource = null,
        string? code_challenge = null,
        string? code_challenge_method = null,
        string? nonce = null,
        string? response_mode = null,
        string? prompt = null,
        int? max_age = null,
        string? login_hint = null,
        string? claims = null,
        string? request_uri = null);
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record AuthorizationCodeStateDTO(
        string id,
        string clientId,
        string state,
        string resource,
        string? redirectUri = null,
        string? scope = null,
        string? codeChallenge = null,
        string? codeChallengeMethod = "S256",
        string? nonce = null,
        string? responseMode = "query",
        string? prompt = null,
        int? maxAge = null,
        string? loginHint = null,
        string? claims = null);
}

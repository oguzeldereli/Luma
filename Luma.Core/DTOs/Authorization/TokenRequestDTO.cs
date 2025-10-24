using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenRequestDTO(
        string grant_type,
        string code,
        string redirect_uri,
        string client_id,
        string client_secret,
        string? code_verifier = null);
}

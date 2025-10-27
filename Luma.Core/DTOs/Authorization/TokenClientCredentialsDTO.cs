using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record TokenClientCredentialsDTO(
        string grant_type,
        string client_id,
        string client_secret,
        string? resource = null,
        string? scope = null);
}

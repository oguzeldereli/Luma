using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Security
{
    public record AccessTokenValidationResult(
    bool IsValid,
    string? Reason = null,
    AccessToken? Token = null)
    {
        public static AccessTokenValidationResult Valid(AccessToken? token = null)
            => new(true, null, token);

        public static AccessTokenValidationResult Invalid(string reason)
            => new(false, reason, null);
    }
}

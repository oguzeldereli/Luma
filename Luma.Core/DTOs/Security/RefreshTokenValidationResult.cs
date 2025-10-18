using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Security
{
    public record RefreshTokenValidationResult(
    bool IsValid,
    string? Reason = null,
    RefreshToken? Token = null)
    {
        public static RefreshTokenValidationResult Valid(RefreshToken? token = null)
            => new(true, null, token);

        public static RefreshTokenValidationResult Invalid(string reason)
            => new(false, reason, null);
    }
}

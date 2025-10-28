using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.DTOs.Authorization
{
    public record UserInfoResponseDTO(
        Guid? sub,
        string? name,
        string? given_name,
        string? family_name,
        string? middle_name,
        string? preferred_username,
        string? nickname,
        string? profile,
        string? picture,
        string? website,
        string? email,
        bool? email_verified,
        string? gender,
        DateOnly? birthdate,
        string? zoneinfo,
        string? locale,
        string? phone_number,
        bool? phone_number_verified,
        string? address,
        DateTime? updated_at
        );
}

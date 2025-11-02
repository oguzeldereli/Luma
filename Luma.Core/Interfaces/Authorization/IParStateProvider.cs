using Luma.Core.DTOs.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IParStateProvider
    {
        Task<string?> StoreParStateAsync(string state);
        Task<string?> RetrieveParStateAsync(string externalId);
        Task<bool> RemoveParStateByStateAsync(string state);
        Task<bool> RemoveParStateByExternalIdAsync(string externalId);
    }
}

using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Services;
using Luma.Core.Services.Authorization;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Extensions
{
    public static class ServiceServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaServices(this IServiceCollection services)
        {
            services.AddScoped<IAuthorizeService, AuthorizeService>();

            return services;
        }
    }
}

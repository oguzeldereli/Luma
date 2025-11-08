using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Providers;
using Luma.Infrastructure.Security;
using Luma.Web.Providers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Extensions
{
    public static class WebServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaWeb(this IServiceCollection services)
        {
            services.AddScoped<IUserLoginSessionCookieAccessor, UserLoginSessionCookieAccessor>();
            services.AddScoped<IAuthorizationCodeStateIdCookieAccessor, AuthCodeStateIdCookieAccessor>();

            return services;
        }
    }
}

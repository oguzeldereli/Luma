using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Security;
using Luma.Infrastructure.Repositories;
using Luma.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Extensions
{
    public static class RepositoryServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaRepositories(this IServiceCollection services)
        {
            services.AddScoped<IMagicLinkTokenRepository, MagicLinkTokenRepository>();
            services.AddScoped<INumericCodeTokenRepository, NumericCodeTokenRepository>();
            services.AddScoped<IAccessTokenRepository, AccessTokenRepository>();
            services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
            services.AddScoped<IUserRepository, UserRepository>();
            return services;
        }
    }
}

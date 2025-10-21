using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Providers;
using Luma.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Extensions
{
    public static class ProvidersServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaProviders(this IServiceCollection services)
        {
            services.AddSingleton<IHmacKeyProvider, HmacKeyProvider>();
            services.AddSingleton<IJwtSigningKeyProvider, JwtSigningKeyProvider>();
            services.AddSingleton<IAuthorizationCodeStateProvider, InMemoryAuthorizationCodeStateProvider>();
            services.AddSingleton<IAuthorizationCodeProvider, InMemoryAuthorizationCodeProvider>();

            services.AddScoped<IRefreshTokenProvider, RefreshTokenProvider>();
            services.AddScoped<IAccessTokenProvider>(sp =>
            {
                var opts = sp.GetRequiredService<IOptions<LumaOptions>>().Value;
                return opts.Tokens.AccessToken.TokenType.ToLowerInvariant() switch
                {
                    "opaque" => ActivatorUtilities.CreateInstance<OpaqueAccessTokenProvider>(sp),
                    "jwt" => ActivatorUtilities.CreateInstance<JwtAccessTokenProvider>(sp),
                    _ => throw new InvalidOperationException($"Unknown token type '{opts.Tokens.AccessToken.TokenType}'")
                };
            });

            return services;
        }
    }
}

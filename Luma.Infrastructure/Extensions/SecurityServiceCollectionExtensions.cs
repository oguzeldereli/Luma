using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Luma.Infrastructure.Extensions
{
    public static class SecurityServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaSecurity(this IServiceCollection services)
        {
            services.AddSingleton<IHmacKeyProvider, HmacKeyProvider>();
            services.AddSingleton<TokenHasher>();
            services.AddSingleton<TokenGenerator>();
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

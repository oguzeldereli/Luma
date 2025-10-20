using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Security;
using Luma.Core.Options;
using Luma.Infrastructure.Providers;
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
            services.AddSingleton<TokenHasher>();
            services.AddSingleton<TokenGenerator>();

            return services;
        }
    }
}

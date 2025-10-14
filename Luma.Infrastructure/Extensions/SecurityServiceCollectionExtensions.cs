using Luma.Core.Interfaces.Security;
using Luma.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Luma.Infrastructure.Extensions
{
    public static class SecurityServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaSecurity(this IServiceCollection services)
        {
            services.AddSingleton<IHmacKeyProvider, HmacKeyProvider>();
            services.AddSingleton<TokenHasher>();
            services.AddSingleton<TokenGenerator>();
            return services;
        }
    }
}

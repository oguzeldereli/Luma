using Luma.Core.Interfaces.Notifications;
using Luma.Core.Options;
using Luma.Infrastructure.Notifications;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Luma.Infrastructure.Extensions
{
    public static class NotificationsServiceCollectionExtensions
    {
        public static IServiceCollection AddLumaNotifications(this IServiceCollection services)
        {
            services.AddScoped<IEmailSender>(sp =>
            {
                var opts = sp.GetRequiredService<IOptions<LumaOptions>>().Value;
                return opts.Email.DeliveryMethod.Trim().ToLowerInvariant() switch
                {
                    "smtp" => ActivatorUtilities.CreateInstance<SmtpEmailSender>(sp),
                    "logging" => ActivatorUtilities.CreateInstance<LoggingEmailSender>(sp),
                    _ => throw new InvalidOperationException(
                        $"Unknown email delivery method '{opts.Email.DeliveryMethod}'. Use 'Logging' or 'Smtp'.")
                };
            });

            return services;
        }
    }
}

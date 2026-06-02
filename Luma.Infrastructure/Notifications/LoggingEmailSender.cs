using Luma.Core.Interfaces.Notifications;
using Luma.Core.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Luma.Infrastructure.Notifications
{
    /// <summary>
    /// Development email sender that writes the message to the application log instead of delivering
    /// it. This makes magic links and numeric codes visible during local development without an SMTP
    /// server. Do not use in production.
    /// </summary>
    public class LoggingEmailSender : IEmailSender
    {
        private readonly ILogger<LoggingEmailSender> _logger;
        private readonly IOptions<LumaOptions> _options;

        public LoggingEmailSender(ILogger<LoggingEmailSender> logger, IOptions<LumaOptions> options)
        {
            _logger = logger;
            _options = options;
        }

        public Task SendAsync(
            string toEmail,
            string subject,
            string htmlBody,
            string? textBody = null,
            CancellationToken cancellationToken = default)
        {
            var from = _options.Value.Email.FromAddress;
            _logger.LogInformation(
                "[Luma email - not actually delivered]\nFrom: {From}\nTo: {To}\nSubject: {Subject}\n{Body}",
                from, toEmail, subject, textBody ?? htmlBody);

            return Task.CompletedTask;
        }
    }
}

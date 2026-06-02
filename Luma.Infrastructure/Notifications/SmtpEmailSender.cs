using Luma.Core.Interfaces.Notifications;
using Luma.Core.Options;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace Luma.Infrastructure.Notifications
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IOptions<LumaOptions> _options;

        public SmtpEmailSender(IOptions<LumaOptions> options)
        {
            _options = options;
        }

        public async Task SendAsync(
            string toEmail,
            string subject,
            string htmlBody,
            string? textBody = null,
            CancellationToken cancellationToken = default)
        {
            var email = _options.Value.Email;
            var smtp = email.Smtp;

            if (string.IsNullOrWhiteSpace(smtp.Host))
                throw new InvalidOperationException("SMTP host is not configured (Luma:Email:Smtp:Host).");

            using var message = new MailMessage
            {
                From = new MailAddress(email.FromAddress, email.FromName),
                Subject = subject,
                Body = htmlBody,
                IsBodyHtml = true
            };
            message.To.Add(toEmail);

            using var client = new SmtpClient(smtp.Host, smtp.Port)
            {
                EnableSsl = smtp.UseStartTls,
                DeliveryMethod = SmtpDeliveryMethod.Network
            };

            if (!string.IsNullOrWhiteSpace(smtp.Username))
                client.Credentials = new NetworkCredential(smtp.Username, smtp.Password);

            await client.SendMailAsync(message, cancellationToken);
        }
    }
}

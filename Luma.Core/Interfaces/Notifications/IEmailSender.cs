namespace Luma.Core.Interfaces.Notifications
{
    public interface IEmailSender
    {
        Task SendAsync(
            string toEmail,
            string subject,
            string htmlBody,
            string? textBody = null,
            CancellationToken cancellationToken = default);
    }
}

namespace Luma.Core.Options
{
    public class EmailOptions
    {
        /// <summary>
        /// How outbound mail is delivered. "Logging" writes the message (including magic links and
        /// numeric codes) to the application log and is intended for local development. "Smtp" sends
        /// the message through the configured SMTP server.
        /// </summary>
        public string DeliveryMethod { get; set; } = "Logging";
        public string FromAddress { get; set; } = "no-reply@luma.local";
        public string FromName { get; set; } = "Luma Auth";
        public SmtpOptions Smtp { get; set; } = new();
    }

    public class SmtpOptions
    {
        public string Host { get; set; } = string.Empty;
        public int Port { get; set; } = 587;
        public bool UseStartTls { get; set; } = true;
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}

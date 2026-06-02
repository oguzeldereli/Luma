using Luma.Core.Interfaces.Auth;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Notifications;
using Luma.Core.Interfaces.Services;
using Luma.Core.Models.Services;
using Luma.Core.Options;
using Luma.Models.Auth;
using Microsoft.Extensions.Options;
using System.Net;

namespace Luma.Core.Services.Authentication
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly IUserRepository _userRepository;
        private readonly IMagicLinkTokenRepository _magicLinkTokens;
        private readonly INumericCodeTokenRepository _numericCodeTokens;
        private readonly IUserClientContractRepository _contracts;
        private readonly IEmailSender _emailSender;
        private readonly IOptions<LumaOptions> _options;

        public AuthenticationService(
            IUserRepository userRepository,
            IMagicLinkTokenRepository magicLinkTokens,
            INumericCodeTokenRepository numericCodeTokens,
            IUserClientContractRepository contracts,
            IEmailSender emailSender,
            IOptions<LumaOptions> options)
        {
            _userRepository = userRepository;
            _magicLinkTokens = magicLinkTokens;
            _numericCodeTokens = numericCodeTokens;
            _contracts = contracts;
            _emailSender = emailSender;
            _options = options;
        }

        public Task<User?> FindUserByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return Task.FromResult<User?>(null);

            return _userRepository.GetByEmailAsync(email.Trim().ToLowerInvariant());
        }

        public async Task<ServiceResponse<User>> RegisterUserAsync(string email, string? firstName, string? lastName)
        {
            if (string.IsNullOrWhiteSpace(email) || !IsValidEmail(email))
                return ServiceResponse<User>.Failure("invalid_email", "A valid email address is required.");

            var normalized = email.Trim().ToLowerInvariant();

            if (await _userRepository.ExistsByEmailAsync(normalized))
                return ServiceResponse<User>.Failure("email_taken", "An account with this email already exists.");

            var user = new User
            {
                Email = normalized,
                FirstName = string.IsNullOrWhiteSpace(firstName) ? null : firstName.Trim(),
                LastName = string.IsNullOrWhiteSpace(lastName) ? null : lastName.Trim(),
                IsEmailVerified = false,
                Status = User.UserStatus.Active
            };

            var created = await _userRepository.CreateAsync(user);
            return ServiceResponse<User>.Success(created);
        }

        public async Task<ServiceResponse<bool>> SendNumericCodeAsync(User user)
        {
            if (!IsUsable(user))
                return ServiceResponse<bool>.Failure("invalid_user", "The account is not able to sign in.");

            var (_, plain) = await _numericCodeTokens.CreateAsync(user.Id);

            var minutes = _options.Value.Tokens.NumericCodeToken.ValidForMinutes;
            var html = $"<p>Your {WebUtility.HtmlEncode(SenderName())} verification code is:</p>" +
                       $"<p style=\"font-size:24px;font-weight:bold;letter-spacing:3px\">{plain}</p>" +
                       $"<p>This code expires in {minutes} minutes. If you did not request it, you can ignore this email.</p>";
            var text = $"Your {SenderName()} verification code is: {plain}\nIt expires in {minutes} minutes.";

            await _emailSender.SendAsync(user.Email, $"{SenderName()} verification code", html, text);
            return ServiceResponse<bool>.Success(true);
        }

        public async Task<ServiceResponse<bool>> SendMagicLinkAsync(User user, Func<string, string> magicLinkUrlBuilder)
        {
            if (!IsUsable(user))
                return ServiceResponse<bool>.Failure("invalid_user", "The account is not able to sign in.");

            var (_, plain) = await _magicLinkTokens.CreateAsync(user.Id);
            var url = magicLinkUrlBuilder(plain);

            var minutes = _options.Value.Tokens.MagicLinkToken.ValidForMinutes;
            var safeUrl = WebUtility.HtmlEncode(url);
            var html = $"<p>Click the link below to sign in to {WebUtility.HtmlEncode(SenderName())}:</p>" +
                       $"<p><a href=\"{safeUrl}\">Sign in</a></p>" +
                       $"<p>Or paste this URL into your browser:<br>{safeUrl}</p>" +
                       $"<p>This link expires in {minutes} minutes. If you did not request it, you can ignore this email.</p>";
            var text = $"Sign in to {SenderName()} using this link (expires in {minutes} minutes):\n{url}";

            await _emailSender.SendAsync(user.Email, $"Sign in to {SenderName()}", html, text);
            return ServiceResponse<bool>.Success(true);
        }

        public async Task<ServiceResponse<long>> VerifyNumericCodeAsync(string code)
        {
            if (string.IsNullOrWhiteSpace(code))
                return ServiceResponse<long>.Failure("invalid_code", "The code is required.");

            var token = await _numericCodeTokens.VerifyAsync(code.Trim());
            if (token == null || token.UserId == null)
                return ServiceResponse<long>.Failure("invalid_code", "The code is invalid or has expired.");

            await _numericCodeTokens.MarkUsedByIdAsync(token.Id);
            await MarkEmailVerifiedAsync(token.UserId.Value);
            return ServiceResponse<long>.Success(token.UserId.Value);
        }

        public async Task<ServiceResponse<long>> VerifyMagicLinkAsync(string token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return ServiceResponse<long>.Failure("invalid_token", "The token is required.");

            var magicToken = await _magicLinkTokens.VerifyAsync(token.Trim());
            if (magicToken == null || magicToken.UserId == null)
                return ServiceResponse<long>.Failure("invalid_token", "The link is invalid or has expired.");

            await _magicLinkTokens.MarkUsedByIdAsync(magicToken.Id);
            await MarkEmailVerifiedAsync(magicToken.UserId.Value);
            return ServiceResponse<long>.Success(magicToken.UserId.Value);
        }

        public Task<bool> HasValidConsentAsync(long userId, string clientId, IEnumerable<string> scopes)
            => _contracts.HasConsentForScopesAsync(userId, clientId, scopes);

        public Task GrantConsentAsync(long userId, string clientId, string scope)
            => _contracts.GrantConsentAsync(userId, clientId, scope);

        private async Task MarkEmailVerifiedAsync(long userId)
        {
            var user = await _userRepository.GetByIdAsync(userId);
            if (user != null && !user.IsEmailVerified)
            {
                user.IsEmailVerified = true;
                await _userRepository.UpdateAsync(user);
            }
        }

        private static bool IsUsable(User? user) =>
            user != null && user.Status == User.UserStatus.Active;

        private string SenderName() => _options.Value.Email.FromName;

        private static bool IsValidEmail(string email)
        {
            try
            {
                var addr = new System.Net.Mail.MailAddress(email);
                return addr.Address == email.Trim();
            }
            catch
            {
                return false;
            }
        }
    }
}

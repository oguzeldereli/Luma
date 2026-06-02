using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Services;
using Luma.Core.Models.Services;
using Luma.Core.Options;
using Luma.Server.Utility;
using Luma.Server.ViewModels;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Luma.Server.Controllers
{
    [Route("/")]
    public class AuthenticationController : Controller
    {
        private readonly IAuthorizationCodeStateIdCookieAccessor _stateCookie;
        private readonly IAuthorizationCodeStateProvider _stateProvider;
        private readonly IUserLoginSessionCookieAccessor _sessionCookie;
        private readonly IUserLoginSessionProvider _sessionProvider;
        private readonly IAuthenticationService _authentication;
        private readonly IAuthorizeService _authorizeService;
        private readonly IClientRepository _clientRepository;
        private readonly IUserRepository _userRepository;
        private readonly IOptions<LumaOptions> _options;

        /*
        Login: user types email -> Choose Method page (or Register if no account)
        Choose Method: user picks magic link or numeric code
            magic link -> Link Sent page (polls until the link is clicked on any device)
            numeric code -> Verify Code page
        On successful authentication:
            if prompt=consent or no prior consent covering the scope -> Consent page
            else -> redirect to client with authorization code
        Select Account (prompt=select_account): continue as current account or use another one.
        */

        public AuthenticationController(
            IAuthorizationCodeStateIdCookieAccessor stateCookie,
            IAuthorizationCodeStateProvider stateProvider,
            IUserLoginSessionCookieAccessor sessionCookie,
            IUserLoginSessionProvider sessionProvider,
            IAuthenticationService authentication,
            IAuthorizeService authorizeService,
            IClientRepository clientRepository,
            IUserRepository userRepository,
            IOptions<LumaOptions> options)
        {
            _stateCookie = stateCookie;
            _stateProvider = stateProvider;
            _sessionCookie = sessionCookie;
            _sessionProvider = sessionProvider;
            _authentication = authentication;
            _authorizeService = authorizeService;
            _clientRepository = clientRepository;
            _userRepository = userRepository;
            _options = options;
        }

        // ----------------------------------------------------------------------------
        // Login (email entry)
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("login")]
        public async Task<IActionResult> Login([FromQuery] string? stateId = null)
        {
            var (ok, cookieStateId, state) = await ResolveStateAsync(stateId);
            if (!ok || state == null)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            return View("Login", new LoginViewModel
            {
                StateId = cookieStateId,
                Email = state.loginHint,
                RegistrationEnabled = _options.Value.AuthenticationServer.EnableUserRegisterationByUI
            });
        }

        [HttpPost]
        [Route("login")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginSubmit(string? email)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var registrationEnabled = _options.Value.AuthenticationServer.EnableUserRegisterationByUI;

            if (string.IsNullOrWhiteSpace(email))
                return View("Login", new LoginViewModel { StateId = stateId, RegistrationEnabled = registrationEnabled, Error = "Please enter your email address." });

            var user = await _authentication.FindUserByEmailAsync(email);
            if (user == null)
            {
                if (registrationEnabled)
                    return RedirectToActionSafe("Register", new { email });

                return View("Login", new LoginViewModel
                {
                    StateId = stateId,
                    Email = email,
                    RegistrationEnabled = false,
                    Error = "No account was found for this email address."
                });
            }

            return RedirectToActionSafe("ChooseMethod", new { email = user.Email });
        }

        // ----------------------------------------------------------------------------
        // Choose method
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("choose-method")]
        public async Task<IActionResult> ChooseMethod([FromQuery] string? email = null)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            if (string.IsNullOrWhiteSpace(email))
                return RedirectToActionSafe("Login", null);

            return View("ChooseMethod", new ChooseMethodViewModel { StateId = stateId, Email = email });
        }

        [HttpPost]
        [Route("choose-method")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChooseMethodSubmit(string? email, string? method)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var user = await _authentication.FindUserByEmailAsync(email ?? "");
            if (user == null)
                return RedirectToActionSafe("Login", null);

            if (method == "code")
            {
                var result = await _authentication.SendNumericCodeAsync(user);
                if (result.ErrorCode != null)
                    return View("ChooseMethod", new ChooseMethodViewModel { StateId = stateId, Email = user.Email, Error = result.ErrorMessage });

                return RedirectToActionSafe("VerifyCode", new { email = user.Email });
            }

            if (method == "magic")
            {
                var baseUrl = $"{Request.Scheme}://{Request.Host}";
                var capturedStateId = stateId;
                var result = await _authentication.SendMagicLinkAsync(user, plainToken =>
                    $"{baseUrl}/magic?token={Uri.EscapeDataString(plainToken)}&state={Uri.EscapeDataString(capturedStateId)}");

                if (result.ErrorCode != null)
                    return View("ChooseMethod", new ChooseMethodViewModel { StateId = stateId, Email = user.Email, Error = result.ErrorMessage });

                return RedirectToActionSafe("LinkSent", new { email = user.Email });
            }

            return View("ChooseMethod", new ChooseMethodViewModel { StateId = stateId, Email = user.Email, Error = "Please choose a sign-in method." });
        }

        // ----------------------------------------------------------------------------
        // Numeric code verification
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("verify-code")]
        public async Task<IActionResult> VerifyCode([FromQuery] string? email = null)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            return View("VerifyCode", new VerifyCodeViewModel { StateId = stateId, Email = email ?? "" });
        }

        [HttpPost]
        [Route("verify-code")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> VerifyCodeSubmit(string? email, string? code)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var result = await _authentication.VerifyNumericCodeAsync(code ?? "");
            if (result.ErrorCode != null)
                return View("VerifyCode", new VerifyCodeViewModel { StateId = stateId, Email = email ?? "", Error = result.ErrorMessage });

            return await CreateSessionAndContinueAsync(result.Data, "numeric_code", stateId);
        }

        // ----------------------------------------------------------------------------
        // Magic link
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("link-sent")]
        public async Task<IActionResult> LinkSent([FromQuery] string? email = null)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            return View("LinkSent", new LinkSentViewModel { StateId = stateId, Email = email ?? "" });
        }

        // The target of the emailed magic link. May be opened on a different device than the one that
        // started the flow, so it does not rely on the state cookie; it carries the state id in the URL.
        [HttpGet]
        [Route("magic")]
        public async Task<IActionResult> MagicLinkCallback([FromQuery] string token, [FromQuery] string state)
        {
            var verify = await _authentication.VerifyMagicLinkAsync(token ?? "");
            if (verify.ErrorCode != null)
                return View("MagicLinkError", new AuthErrorViewModel { Error = verify.ErrorCode, Description = verify.ErrorMessage });

            var storedState = string.IsNullOrWhiteSpace(state) ? null : await _stateProvider.GetAsync(state);
            if (storedState == null)
                return View("MagicLinkError", new AuthErrorViewModel { Error = "invalid_login_state", Description = "This sign-in request has expired. Please start again." });

            // Mark the pending authorization as authenticated so the original tab/device can complete it.
            var updated = storedState with { authenticatedUserId = verify.Data, authMethod = "magic_link" };
            await _stateProvider.SaveAsync(state, updated, _options.Value.AuthenticationServer.AuthCodeStateIdCookieValidForMinutes * 60);

            return View("MagicLinkVerified");
        }

        // Polled by the Link Sent page. Reports whether the magic link has been clicked yet.
        [HttpGet]
        [Route("magic/status")]
        public async Task<IActionResult> MagicLinkStatus()
        {
            var stateId = _stateCookie.GetAuthCodeStateIdToken();
            if (string.IsNullOrEmpty(stateId))
                return Json(new { authenticated = false, expired = true });

            var state = await _stateProvider.GetAsync(stateId);
            if (state == null)
                return Json(new { authenticated = false, expired = true });

            return Json(new { authenticated = state.authenticatedUserId != null, expired = false });
        }

        // Called by the original browser once polling reports authentication.
        [HttpGet]
        [Route("magic/complete")]
        public async Task<IActionResult> MagicLinkComplete()
        {
            var (ok, stateId, state) = await ResolveStateAsync(null);
            if (!ok || state?.authenticatedUserId is not { } userId)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            return await CreateSessionAndContinueAsync(userId, state.authMethod ?? "magic_link", stateId);
        }

        // ----------------------------------------------------------------------------
        // Consent
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("consent")]
        public async Task<IActionResult> Consent([FromQuery] string? stateId = null)
        {
            var (ok, cookieStateId, state) = await ResolveStateAsync(stateId);
            if (!ok || state == null)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var session = await GetCurrentSessionUserAsync();
            if (session == null)
                return RedirectToActionSafe("Login", null);

            var client = _clientRepository.FindClientById(state.clientId);
            var scopes = (state.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);

            return View("Consent", new ConsentViewModel
            {
                StateId = cookieStateId,
                ClientName = client?.DisplayName ?? state.clientId,
                Email = session.Email,
                Scopes = scopes
            });
        }

        [HttpPost]
        [Route("consent")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ConsentSubmit(string? action)
        {
            var (ok, stateId, state) = await ResolveStateAsync(null);
            if (!ok || state == null)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var session = await GetCurrentSessionUserAsync();
            if (session == null)
                return RedirectToActionSafe("Login", null);

            if (action == "deny")
            {
                _stateCookie.ClearAuthCodeStateIdToken();
                return OAuthServiceResponse<object>
                    .Failure("access_denied", "The user denied the authorization request.", 302, null,
                             state.state, state.redirectUri, state.responseMode)
                    .ToErrorResponse();
            }

            await _authentication.GrantConsentAsync(session.Id, state.clientId, state.scope ?? "");
            return await GenerateCodeAndRedirectAsync(session.Id, stateId);
        }

        // ----------------------------------------------------------------------------
        // Select account (prompt=select_account)
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("select-account")]
        public async Task<IActionResult> SelectAccount([FromQuery] string? stateId = null)
        {
            var (ok, cookieStateId, _) = await ResolveStateAsync(stateId);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var session = await GetCurrentSessionUserAsync();
            if (session == null)
                return RedirectToActionSafe("Login", null);

            return View("SelectAccount", new SelectAccountViewModel { StateId = cookieStateId, Email = session.Email });
        }

        [HttpPost]
        [Route("select-account")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SelectAccountSubmit(string? action)
        {
            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var token = _sessionCookie.GetLoginSessionToken();
            var session = string.IsNullOrEmpty(token) ? null : await _sessionProvider.GetBySessionTokenAsync(token);

            if (action == "use_other" || session == null)
            {
                if (session != null)
                    await _sessionProvider.RevokeAsync(session.Id, "User chose a different account");
                _sessionCookie.ClearLoginSessionToken();
                return RedirectToActionSafe("Login", null);
            }

            // Continue with the existing session (no new session needed).
            return await ContinueAfterAuthAsync(session.UserId, stateId);
        }

        // ----------------------------------------------------------------------------
        // Registration
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("register")]
        public async Task<IActionResult> Register([FromQuery] string? email = null)
        {
            if (!_options.Value.AuthenticationServer.EnableUserRegisterationByUI)
                return ErrorView("registration_disabled", "Self-service registration is disabled.");

            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            return View("Register", new RegisterViewModel { StateId = stateId, Email = email ?? "" });
        }

        [HttpPost]
        [Route("register")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterSubmit(string? email, string? firstName, string? lastName)
        {
            if (!_options.Value.AuthenticationServer.EnableUserRegisterationByUI)
                return ErrorView("registration_disabled", "Self-service registration is disabled.");

            var (ok, stateId, _) = await ResolveStateAsync(null);
            if (!ok)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var result = await _authentication.RegisterUserAsync(email ?? "", firstName, lastName);
            if (result.ErrorCode != null || result.Data == null)
                return View("Register", new RegisterViewModel
                {
                    StateId = stateId,
                    Email = email ?? "",
                    FirstName = firstName,
                    LastName = lastName,
                    Error = result.ErrorMessage
                });

            return RedirectToActionSafe("ChooseMethod", new { email = result.Data.Email });
        }

        // ----------------------------------------------------------------------------
        // Profile (basic account view for a signed-in user)
        // ----------------------------------------------------------------------------

        [HttpGet]
        [Route("profile")]
        public async Task<IActionResult> Profile()
        {
            var session = await GetCurrentSessionUserAsync();
            if (session == null)
                return ErrorView("not_authenticated", "You are not signed in.");

            return View("Profile", new ProfileViewModel
            {
                Email = session.Email,
                FullName = session.GetFullName(),
                EmailVerified = session.IsEmailVerified
            });
        }

        [HttpGet]
        [Route("error")]
        public IActionResult Error([FromQuery] string? error = null, [FromQuery] string? description = null)
        {
            return View("Error", new AuthErrorViewModel { Error = error ?? "unknown_error", Description = description });
        }

        // ----------------------------------------------------------------------------
        // Shared flow helpers
        // ----------------------------------------------------------------------------

        private async Task<IActionResult> CreateSessionAndContinueAsync(long userId, string authMethod, string stateId)
        {
            var state = await _stateProvider.GetAsync(stateId);
            var clientId = state?.clientId;

            var (plain, _) = await _sessionProvider.CreateAsync(
                userId,
                ipAddress: HttpContext.Connection.RemoteIpAddress?.ToString(),
                userAgent: Request.Headers.UserAgent.ToString(),
                clientId: clientId,
                authMethod: authMethod);

            _sessionCookie.SetLoginSessionToken(plain);

            return await ContinueAfterAuthAsync(userId, stateId);
        }

        private async Task<IActionResult> ContinueAfterAuthAsync(long userId, string stateId)
        {
            var state = await _stateProvider.GetAsync(stateId);
            if (state == null)
                return ErrorView("invalid_login_state", "Your sign-in session is missing or has expired. Please start again.");

            var scopes = (state.scope ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var prompts = (state.prompt ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var needsConsent = prompts.Contains("consent")
                || !await _authentication.HasValidConsentAsync(userId, state.clientId, scopes);

            if (needsConsent)
                return RedirectToActionSafe("Consent", null);

            return await GenerateCodeAndRedirectAsync(userId, stateId);
        }

        private async Task<IActionResult> GenerateCodeAndRedirectAsync(long userId, string stateId)
        {
            var auth = await _authorizeService.GenerateAuthorizationCodeAsync(userId, stateId);
            if (!string.IsNullOrWhiteSpace(auth.ErrorCode) || auth.Data == null)
                return auth.ToErrorResponse();

            _stateCookie.ClearAuthCodeStateIdToken();
            return AuthorizationResponseBuilder.BuildCodeResponse(auth.Data, auth.State, auth.RedirectUri!, auth.ResponseMode);
        }

        private async Task<Luma.Models.Auth.User?> GetCurrentSessionUserAsync()
        {
            var token = _sessionCookie.GetLoginSessionToken();
            if (string.IsNullOrEmpty(token))
                return null;

            var session = await _sessionProvider.GetBySessionTokenAsync(token);
            if (session == null)
                return null;

            return await _userRepository.GetByIdAsync(session.UserId);
        }

        // Resolves the active authorization state from the state-id cookie. When a stateId is provided
        // (from a query string), it must match the cookie.
        private async Task<(bool ok, string stateId, AuthorizationCodeStateDTO? state)> ResolveStateAsync(string? stateId)
        {
            var cookie = _stateCookie.GetAuthCodeStateIdToken();
            if (string.IsNullOrEmpty(cookie))
                return (false, "", null);

            if (!string.IsNullOrEmpty(stateId) && stateId != cookie)
                return (false, "", null);

            var state = await _stateProvider.GetAsync(cookie);
            return (state != null, cookie, state);
        }

        private IActionResult ErrorView(string error, string? description = null)
            => View("Error", new AuthErrorViewModel { Error = error, Description = description });

        // Attribute-routed actions are reached by their route templates, so redirect by path.
        private IActionResult RedirectToActionSafe(string action, object? query)
        {
            var path = action switch
            {
                "Login" => "/login",
                "Register" => "/register",
                "ChooseMethod" => "/choose-method",
                "VerifyCode" => "/verify-code",
                "LinkSent" => "/link-sent",
                "Consent" => "/consent",
                "SelectAccount" => "/select-account",
                _ => "/login"
            };

            if (query == null)
                return Redirect(path);

            var dict = new Dictionary<string, string?>();
            foreach (var prop in query.GetType().GetProperties())
            {
                var value = prop.GetValue(query)?.ToString();
                if (!string.IsNullOrEmpty(value))
                    dict[prop.Name] = value;
            }

            return Redirect(Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(path, dict));
        }
    }
}

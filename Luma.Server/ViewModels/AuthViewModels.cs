namespace Luma.Server.ViewModels
{
    public class LoginViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string? Email { get; set; }
        public bool RegistrationEnabled { get; set; }
        public string? Error { get; set; }
    }

    public class ChooseMethodViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? Error { get; set; }
    }

    public class VerifyCodeViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? Error { get; set; }
    }

    public class LinkSentViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }

    public class ConsentViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string ClientName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public IReadOnlyList<string> Scopes { get; set; } = new List<string>();
    }

    public class SelectAccountViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
    }

    public class RegisterViewModel
    {
        public string StateId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Error { get; set; }
    }

    public class AuthErrorViewModel
    {
        public string Error { get; set; } = "unknown_error";
        public string? Description { get; set; }
    }

    public class ProfileViewModel
    {
        public string Email { get; set; } = string.Empty;
        public string? FullName { get; set; }
        public bool EmailVerified { get; set; }
    }
}

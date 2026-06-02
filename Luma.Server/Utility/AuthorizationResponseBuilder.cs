using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System.Text.Encodings.Web;

namespace Luma.Server.Utility
{
    /// <summary>
    /// Builds the successful authorization-code response sent back to the client, honoring the
    /// requested response_mode (query redirect or auto-submitting form_post).
    /// </summary>
    public static class AuthorizationResponseBuilder
    {
        public static IActionResult BuildCodeResponse(string code, string? state, string redirectUri, string? responseMode)
        {
            if (string.Equals(responseMode, "form_post", StringComparison.OrdinalIgnoreCase))
            {
                var encoder = HtmlEncoder.Default;
                var stateField = string.IsNullOrEmpty(state)
                    ? string.Empty
                    : $"<input type='hidden' name='state' value='{encoder.Encode(state)}' />";

                var html =
                    "<html><body onload=\"document.forms[0].submit()\">" +
                    $"<form method='post' action='{encoder.Encode(redirectUri)}'>" +
                    $"<input type='hidden' name='code' value='{encoder.Encode(code)}' />" +
                    stateField +
                    "</form></body></html>";

                return new ContentResult
                {
                    ContentType = "text/html",
                    Content = html
                };
            }

            var queryParams = new Dictionary<string, string?> { ["code"] = code };
            if (!string.IsNullOrEmpty(state))
                queryParams["state"] = state;

            var url = QueryHelpers.AddQueryString(redirectUri, queryParams);
            return new RedirectResult(url);
        }
    }
}

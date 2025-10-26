using Luma.Core.Models.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Luma.Server.Utility
{
    public static class OAuthResponseHelper
    {
        public static IActionResult ToErrorResponse<T>(this OAuthServiceResponse<T> result)
        {
            if (result == null)
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);

            if (string.IsNullOrEmpty(result.ErrorCode))
                throw new InvalidOperationException("The OAuthServiceResponse does not represent an error.");

            if (string.Equals(result.ResponseMode, "form_post", StringComparison.OrdinalIgnoreCase))
            {
                var html = $@"
                    <html><body onload=""document.forms[0].submit()"">
                        <form method='post' action='{result.RedirectUri}'>
                            <input type='hidden' name='error' value='{result.ErrorCode}' />
                            <input type='hidden' name='error_description' value='{result.ErrorMessage}' />
                            {(string.IsNullOrEmpty(result.ErrorUri) ? "" : $"<input type='hidden' name='error_uri' value='{result.ErrorUri}' />")}
                            {(string.IsNullOrEmpty(result.State) ? "" : $"<input type='hidden' name='state' value='{result.State}' />")}
                        </form>
                    </body></html>";

                return new ContentResult
                {
                    ContentType = "text/html",
                    StatusCode = StatusCodes.Status200OK,
                    Content = html
                };
            }

            if (!string.IsNullOrEmpty(result.RedirectUri))
            {
                var queryParams = new List<string>();

                void AddParam(string key, string? value)
                {
                    if (!string.IsNullOrEmpty(value))
                        queryParams.Add($"{key}={Uri.EscapeDataString(value)}");
                }

                AddParam("error", result.ErrorCode);
                AddParam("error_description", result.ErrorMessage);
                AddParam("error_uri", result.ErrorUri);
                AddParam("state", result.State);

                var separator = result.RedirectUri.Contains("?") ? "&" : "?";
                var redirectUrl = $"{result.RedirectUri}{separator}{string.Join("&", queryParams)}";

                return new RedirectResult(redirectUrl, false);
            }

            var errorResponse = new
            {
                error = result.ErrorCode,
                error_description = result.ErrorMessage,
                error_uri = string.IsNullOrWhiteSpace(result.ErrorUri) ? null : result.ErrorUri,
                state = result.State
            };

            var statusCode = result.StatusCode ?? StatusCodes.Status400BadRequest;

            return new ObjectResult(errorResponse) { StatusCode = statusCode };
        }
    }
}

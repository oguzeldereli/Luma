using Luma.Core.Models.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Luma.Server.Utility
{
    public static class OAuthResponseHelper
    {
        public static IActionResult ToErrorResponse<T>(this OAuthServiceResponse<T> result, bool redirectSafe, string? redirectUri = null, string? responseMode = null)
        {
            if (result == null)
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);

            // throw if this is not an error response
            if (string.IsNullOrEmpty(result.ErrorCode))
                throw new InvalidOperationException("The OAuthServiceResponse does not represent an error.");

            if (redirectSafe && responseMode == "form_post" && !string.IsNullOrWhiteSpace(redirectUri))
            {
                var html = $@"
                    <html><body onload=""document.forms[0].submit()"">
                        <form method='post' action='{redirectUri}'>
                            <input type='hidden' name='error' value='{result.ErrorCode}' />
                            <input type='hidden' name='error_description' value='{result.ErrorMessage}' />
                            {(string.IsNullOrEmpty(result.State) ? "" : $"<input type='hidden' name='state' value='{result.State}' />")}
                        </form>
                    </body></html>";

                return new ContentResult { ContentType = "text/html", Content = html };
            }
            else if (redirectSafe && !string.IsNullOrWhiteSpace(redirectUri))
            {
                var uri = QueryHelpers.AddQueryString(redirectUri ?? "", new Dictionary<string, string?>
                {
                    ["error"] = result.ErrorCode,
                    ["error_description"] = result.ErrorMessage,
                    ["state"] = result.State,
                    ["error_uri"] = string.IsNullOrWhiteSpace(result.ErrorUri) ? null : result.ErrorUri
                });
                return new RedirectResult(uri);
            }
            else
            {
                var errorResponse = new
                {
                    error = result.ErrorCode,
                    error_description = result.ErrorMessage,
                    state = result.State,
                    error_uri = string.IsNullOrWhiteSpace(result.ErrorUri) ? null : result.ErrorUri
                };

                var statusCode = GetStatusCodeForError(result.ErrorCode);
                return new ObjectResult(errorResponse)
                {
                    StatusCode = statusCode
                };
            }
        }

        private static int GetStatusCodeForError(string errorCode)
        {
            return errorCode switch
            {
                // 400 — Bad Request: malformed or invalid request
                "invalid_request" => StatusCodes.Status400BadRequest,
                "invalid_scope" => StatusCodes.Status400BadRequest,
                "unsupported_grant_type" => StatusCodes.Status400BadRequest,
                "unsupported_response_type" => StatusCodes.Status400BadRequest,
                "unauthorized_client" => StatusCodes.Status400BadRequest,

                // 401 — Unauthorized: invalid client credentials or token
                "invalid_client" => StatusCodes.Status401Unauthorized,
                "invalid_token" => StatusCodes.Status401Unauthorized,

                // 403 — Forbidden: user or client not permitted
                "access_denied" => StatusCodes.Status403Forbidden,

                // 500 — Server error
                "server_error" => StatusCodes.Status500InternalServerError,

                // 503 — Temporarily unavailable
                "temporarily_unavailable" => StatusCodes.Status503ServiceUnavailable,

                // 302 — Interaction required (OIDC)
                "interaction_required" => StatusCodes.Status302Found,
                "login_required" => StatusCodes.Status302Found,
                "consent_required" => StatusCodes.Status302Found,
                "account_selection_required" => StatusCodes.Status302Found,

                // Default fallback
                _ => StatusCodes.Status400BadRequest
            };
        }
    }
}

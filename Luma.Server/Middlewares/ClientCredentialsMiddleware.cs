namespace Luma.Server.Middlewares
{
    using System;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Primitives;

    namespace YourNamespace.Middleware
    {
        public class ClientCredentialsMiddleware
        {
            private readonly RequestDelegate _next;

            public ClientCredentialsMiddleware(RequestDelegate next)
            {
                _next = next;
            }

            public async Task InvokeAsync(HttpContext context)
            {
                string? clientId = null;
                string? clientSecret = null;

                if (context.Request.Headers.TryGetValue("Authorization", out StringValues authHeader) &&
                    authHeader.ToString().StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var encoded = authHeader.ToString().Substring("Basic ".Length).Trim();
                        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
                        var parts = decoded.Split(':', 2);

                        if (parts.Length == 2)
                        {
                            clientId = parts[0];
                            clientSecret = parts[1];
                        }
                    }
                    catch
                    {
                        // Ignore decoding errors — may not be valid Base64
                    }
                }

                if (string.IsNullOrEmpty(clientId) && context.Request.HasFormContentType)
                {
                    var form = await context.Request.ReadFormAsync();

                    if (form.TryGetValue("client_id", out var formClientId))
                        clientId = formClientId;

                    if (form.TryGetValue("client_secret", out var formClientSecret))
                        clientSecret = formClientSecret;
                }

                if (!string.IsNullOrEmpty(clientId))
                    context.Items["ClientId"] = clientId;

                if (!string.IsNullOrEmpty(clientSecret))
                    context.Items["ClientSecret"] = clientSecret;

                await _next(context);
            }
        }

        public static class ClientCredentialsMiddlewareExtensions
        {
            public static IApplicationBuilder UseClientCredentialsMiddleware(this IApplicationBuilder builder)
            {
                return builder.UseMiddleware<ClientCredentialsMiddleware>();
            }
        }
    }

}

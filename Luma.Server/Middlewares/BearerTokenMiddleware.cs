namespace Luma.Server.Middlewares
{
    using System;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.Extensions.Primitives;

    namespace YourNamespace.Middleware
    {
        public class BearerTokenMiddleware
        {
            private readonly RequestDelegate _next;

            public BearerTokenMiddleware(RequestDelegate next)
            {
                _next = next;
            }

            public async Task InvokeAsync(HttpContext context)
            {
                string? bearerToken = null;

                if (context.Request.Headers.TryGetValue("Authorization", out StringValues authHeader) &&
                    authHeader.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    var token = authHeader.ToString().Substring("Bearer ".Length).Trim();
                    bearerToken = token;
                }

                if (!string.IsNullOrEmpty(bearerToken))
                    context.Items["BearerToken"] = bearerToken;

                await _next(context);
            }
        }
        
        public static class BearerTokenMiddlewareExtensions
        {
            public static IApplicationBuilder UseBearerTokenMiddleware(this IApplicationBuilder builder)
            {
                return builder.UseMiddleware<BearerTokenMiddleware>();
            }
        }
    }

}

using Luma.Core.Models.Services;
using Microsoft.AspNetCore.Mvc;

namespace Luma.Server.Utility
{
    public static class ResultExtensions
    {
        public static IActionResult WithHeaders(this ObjectResult result, IDictionary<string, string> headers)
            => new HeaderObjectResult(result.Value!, result.StatusCode, headers);
    }

    public class HeaderObjectResult : ObjectResult
    {
        private readonly IDictionary<string, string> _headers;

        public HeaderObjectResult(object? value, int? statusCode = null, IDictionary<string, string>? headers = null)
            : base(value)
        {
            StatusCode = statusCode;
            _headers = headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public override async Task ExecuteResultAsync(ActionContext context)
        {
            var response = context.HttpContext.Response;

            foreach (var header in _headers)
            {
                if (!response.Headers.ContainsKey(header.Key))
                    response.Headers.Append(header.Key, header.Value);
            }

            await base.ExecuteResultAsync(context);
        }
    }

}

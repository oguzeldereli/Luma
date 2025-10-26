using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Services
{
    public class OAuthServiceResponse<T>
    {
        public T? Data { get; private set; }
        public int? StatusCode { get; private set; } = null;
        public string? ErrorCode { get; private set; } = null;
        public string? ErrorMessage { get; private set; } = null;
        public string? ErrorUri { get; private set; } = null;
        public string? RedirectUri { get; private set; } = null;
        public string? State { get; private set; } = null;
        public string? ResponseMode { get; private set; } = null;

        protected OAuthServiceResponse() { }

        public static OAuthServiceResponse<T> Success(
            T data,
            int? statusCode = null,
            string? state = null, 
            string? redirectUri = null,
            string? responseMode = null)
        {
            return new OAuthServiceResponse<T>
            {
                Data = data,
                State = state,
                RedirectUri = redirectUri,
                StatusCode = statusCode,
                ResponseMode = responseMode
            };
        }

        public static OAuthServiceResponse<T> Failure(
            string errorCode, 
            string errorMessage,
            int statusCode,
            string? errorUri = null,
            string? state = null, 
            string? redirectUri = null,
            string? responseMode = null)
        {
            return new OAuthServiceResponse<T>
            {
                ErrorCode = errorCode,
                ErrorMessage = errorMessage,
                State = state,
                ErrorUri = errorUri,
                RedirectUri = redirectUri,
                StatusCode = statusCode,
                ResponseMode = responseMode
            };
        }
    }
}

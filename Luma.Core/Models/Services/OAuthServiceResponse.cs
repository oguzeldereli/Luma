using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Services
{
    public class OAuthServiceResponse<T>
    {
        public T? Data { get; set; }
        public string ErrorCode { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;
        public string ErrorUri { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;

        protected OAuthServiceResponse() { }

        public static OAuthServiceResponse<T> Success(T data, string state)
        {
            return new OAuthServiceResponse<T>
            {
                Data = data,
                State = state
            };
        }

        public static OAuthServiceResponse<T> Failure(string errorCode, string errorMessage, string state, string? errorUri = null)
        {
            return new OAuthServiceResponse<T>
            {
                ErrorCode = errorCode,
                ErrorMessage = errorMessage,
                State = state,
                ErrorUri = errorUri ?? string.Empty
            };
        }
    }
}

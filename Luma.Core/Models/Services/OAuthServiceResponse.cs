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
        public string? ErrorCode { get; set; } = null;
        public string? ErrorMessage { get; set; } = null;
        public string? ErrorUri { get; set; } = null;
        public string? State { get; set; } = null;

        protected OAuthServiceResponse() { }

        public static OAuthServiceResponse<T> Success(T data, string? state)
        {
            return new OAuthServiceResponse<T>
            {
                Data = data,
                State = state
            };
        }

        public static OAuthServiceResponse<T> Failure(string errorCode, string errorMessage, string? state, string? errorUri = null)
        {
            return new OAuthServiceResponse<T>
            {
                ErrorCode = errorCode,
                ErrorMessage = errorMessage,
                State = state,
                ErrorUri = errorUri
            };
        }
    }
}

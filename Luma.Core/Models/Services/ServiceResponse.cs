using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Models.Services
{
    public class ServiceResponse<T>
    {
        public T? Data { get; set; }
        public string ErrorCode { get; set; } = string.Empty;
        public string ErrorMessage { get; set; } = string.Empty;

        protected ServiceResponse() { }

        public static ServiceResponse<T> Success(T data)
        {
            return new ServiceResponse<T>
            {
                Data = data
            };
        }

        public static ServiceResponse<T> Failure(string errorCode, string errorMessage)
        {
            return new ServiceResponse<T>
            {
                ErrorCode = errorCode,
                ErrorMessage = errorMessage
            };
        }
    }
}

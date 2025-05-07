using System.Collections.Generic;

namespace AuthSystem.Application.DTOs
{
    public class ApiResponseDto<T>
    {
        public bool Succeeded { get; set; }
        public string Message { get; set; }
        public string ErrorCode { get; set; }
        public T Data { get; set; }
        public List<string> Errors { get; set; } = new List<string>();

        public static ApiResponseDto<T> Success(T data, string message = null)
        {
            return new ApiResponseDto<T>
            {
                Succeeded = true,
                Data = data,
                Message = message
            };
        }

        public static ApiResponseDto<T> Failure(string errorMessage, string errorCode = null)
        {
            return new ApiResponseDto<T>
            {
                Succeeded = false,
                Message = errorMessage,
                ErrorCode = errorCode
            };
        }

        public static ApiResponseDto<T> Failure(List<string> errors, string errorCode = null)
        {
            return new ApiResponseDto<T>
            {
                Succeeded = false,
                Errors = errors,
                ErrorCode = errorCode
            };
        }
    }
}
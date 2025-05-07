using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthSystem.API.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();

            var requestId = Guid.NewGuid().ToString();
            context.Items["RequestId"] = requestId;

            var requestMethod = context.Request.Method;
            var requestPath = context.Request.Path;
            var userIp = context.Connection.RemoteIpAddress?.ToString();
            var userAgent = context.Request.Headers["User-Agent"].ToString();

            _logger.LogInformation(
                "Request {RequestId} started: {RequestMethod} {RequestPath} - IP: {UserIp}, UserAgent: {UserAgent}",
                requestId, requestMethod, requestPath, userIp, userAgent);

            try
            {
                await _next(context);

                stopwatch.Stop();

                _logger.LogInformation(
                    "Request {RequestId} completed: {RequestMethod} {RequestPath} - Status: {StatusCode} in {ElapsedMilliseconds}ms",
                    requestId, requestMethod, requestPath, context.Response.StatusCode, stopwatch.ElapsedMilliseconds);
            }
            catch (Exception)
            {
                stopwatch.Stop();

                _logger.LogInformation(
                    "Request {RequestId} failed: {RequestMethod} {RequestPath} in {ElapsedMilliseconds}ms",
                    requestId, requestMethod, requestPath, stopwatch.ElapsedMilliseconds);

                throw;
            }
        }
    }
}
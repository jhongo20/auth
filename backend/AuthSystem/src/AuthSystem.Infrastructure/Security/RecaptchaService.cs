using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Security/RecaptchaService.cs
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;
using Microsoft.Extensions.Options;

namespace AuthSystem.Infrastructure.Security
{
    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly RecaptchaSettings _settings;

        public RecaptchaService(HttpClient httpClient, IOptions<RecaptchaSettings> settings)
        {
            _httpClient = httpClient;
            _settings = settings.Value;
        }

        public async Task<bool> ValidateTokenAsync(string token, string ipAddress)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            var response = await _httpClient.GetStringAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={_settings.SecretKey}&response={token}&remoteip={ipAddress}");

            var recaptchaResponse = JsonSerializer.Deserialize<RecaptchaResponse>(response);

            return recaptchaResponse?.Success == true && recaptchaResponse.Score >= _settings.MinimumScore;
        }

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public float Score { get; set; }
            public string Action { get; set; }
            public string Hostname { get; set; }
        }
    }

    public class RecaptchaSettings
    {
        public string SiteKey { get; set; }
        public string SecretKey { get; set; }
        public float MinimumScore { get; set; } = 0.5f;
    }
}

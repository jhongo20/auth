using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Email/EmailService.cs
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;
using Microsoft.Extensions.Options;

namespace AuthSystem.Infrastructure.Email
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _emailSettings;

        public EmailService(IOptions<EmailSettings> emailSettings)
        {
            _emailSettings = emailSettings.Value;
        }

        public async Task SendAsync(string to, string subject, string body, bool isHtml = true)
        {
            var message = new MailMessage
            {
                From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
                Subject = subject,
                Body = body,
                IsBodyHtml = isHtml
            };

            message.To.Add(to);

            using var client = new SmtpClient(_emailSettings.SmtpHost, _emailSettings.SmtpPort)
            {
                EnableSsl = _emailSettings.EnableSsl,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_emailSettings.Username, _emailSettings.Password)
            };

            await client.SendMailAsync(message);
        }

        public async Task SendConfirmationEmailAsync(string email, string userId, string token)
        {
            var callbackUrl = $"{_emailSettings.WebsiteBaseUrl}/auth/confirm-email?userId={userId}&token={token}";

            var subject = "Confirma tu cuenta";
            var body = $@"
                <h1>Gracias por registrarte</h1>
                <p>Por favor confirma tu cuenta haciendo clic en el siguiente enlace:</p>
                <p><a href='{callbackUrl}'>Confirmar cuenta</a></p>
                <p>Si no puedes hacer clic en el enlace, copia y pega la siguiente URL en tu navegador:</p>
                <p>{callbackUrl}</p>
                <p>Si no has solicitado este correo, puedes ignorarlo.</p>
            ";

            await SendAsync(email, subject, body);
        }

        public async Task SendPasswordResetEmailAsync(string email, string userId, string token)
        {
            var callbackUrl = $"{_emailSettings.WebsiteBaseUrl}/auth/reset-password?userId={userId}&token={token}";

            var subject = "Recuperación de contraseña";
            var body = $@"
                <h1>Recuperación de contraseña</h1>
                <p>Hemos recibido una solicitud para restablecer tu contraseña. Haz clic en el siguiente enlace para proceder:</p>
                <p><a href='{callbackUrl}'>Restablecer contraseña</a></p>
                <p>Si no puedes hacer clic en el enlace, copia y pega la siguiente URL en tu navegador:</p>
                <p>{callbackUrl}</p>
                <p>Si no has solicitado este correo, puedes ignorarlo.</p>
                <p>Este enlace expirará en 24 horas.</p>
            ";

            await SendAsync(email, subject, body);
        }

        public async Task SendTwoFactorCodeAsync(string email, string code)
        {
            var subject = "Código de verificación";
            var body = $@"
                <h1>Código de verificación</h1>
                <p>Tu código de verificación es:</p>
                <h2 style='font-size: 32px; letter-spacing: 5px; text-align: center; padding: 20px; background-color: #f5f5f5; border-radius: 5px;'>{code}</h2>
                <p>Este código expirará en 5 minutos.</p>
                <p>Si no has solicitado este código, alguien podría estar intentando acceder a tu cuenta.</p>
            ";

            await SendAsync(email, subject, body);
        }
    }

    public class EmailSettings
    {
        public string FromEmail { get; set; }
        public string FromName { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public bool EnableSsl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string WebsiteBaseUrl { get; set; }
    }
}

using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IEmailService
    {
        Task SendAsync(string to, string subject, string body, bool isHtml = true);
        Task SendConfirmationEmailAsync(string email, string userId, string token);
        Task SendPasswordResetEmailAsync(string email, string userId, string token);
        Task SendTwoFactorCodeAsync(string email, string code);
    }
}

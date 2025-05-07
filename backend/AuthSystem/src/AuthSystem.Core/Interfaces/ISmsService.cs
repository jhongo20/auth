using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface ISmsService
    {
        Task SendAsync(string phoneNumber, string message);
        Task SendVerificationCodeAsync(string phoneNumber, string code);
    }
}

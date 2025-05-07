using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IRecaptchaService
    {
        Task<bool> ValidateTokenAsync(string token, string ipAddress);
    }
}

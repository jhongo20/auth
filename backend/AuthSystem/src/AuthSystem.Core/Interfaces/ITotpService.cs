using System.Collections.Generic;

namespace AuthSystem.Core.Interfaces
{
    public interface ITotpService
    {
        string GenerateSecretKey();
        string GenerateCode(string secretKey);
        bool ValidateCode(string secretKey, string code);
        string[] GenerateRecoveryCodes(int numberOfCodes = 8);
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Security/TotpService.cs
using AuthSystem.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace AuthSystem.Infrastructure.Security
{
    public class TotpService : ITotpService
    {
        private const int DefaultStep = 30;
        private const int DefaultDigits = 6;

        public string GenerateSecretKey()
        {
            var key = new byte[20];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return Convert.ToBase64String(key);
        }

        public string GenerateCode(string secretKey)
        {
            var counter = GetCurrentCounter();
            return GenerateCodeInternal(secretKey, counter);
        }

        public bool ValidateCode(string secretKey, string code)
        {
            if (string.IsNullOrEmpty(secretKey) || string.IsNullOrEmpty(code))
            {
                return false;
            }

            // Permitir un margen de un paso anterior y uno posterior para compensar desincronización
            var currentCounter = GetCurrentCounter();

            // Verificar código actual
            if (GenerateCodeInternal(secretKey, currentCounter) == code)
            {
                return true;
            }

            // Verificar código anterior
            if (GenerateCodeInternal(secretKey, currentCounter - 1) == code)
            {
                return true;
            }

            // Verificar código siguiente
            if (GenerateCodeInternal(secretKey, currentCounter + 1) == code)
            {
                return true;
            }

            return false;
        }

        public string[] GenerateRecoveryCodes(int numberOfCodes = 8)
        {
            var codes = new string[numberOfCodes];
            using var rng = RandomNumberGenerator.Create();

            for (int i = 0; i < numberOfCodes; i++)
            {
                var codeBytes = new byte[10]; // 10 bytes = 20 caracteres en hex
                rng.GetBytes(codeBytes);
                codes[i] = BitConverter.ToString(codeBytes).Replace("-", "").ToLower();
            }

            return codes;
        }

        private long GetCurrentCounter()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() / DefaultStep;
        }

        private string GenerateCodeInternal(string secretKey, long counter)
        {
            // Decodificar clave secreta
            byte[] key = Convert.FromBase64String(secretKey);

            // Convertir contador a bytes (big-endian)
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            // Asegurar que counterBytes tiene 8 bytes
            byte[] paddedCounter = new byte[8];
            Array.Copy(counterBytes, 0, paddedCounter, 8 - counterBytes.Length, counterBytes.Length);

            // Calcular HMAC-SHA1
            using var hmac = new HMACSHA1(key);
            byte[] hash = hmac.ComputeHash(paddedCounter);

            // Extraer un valor de 4 bytes basado en el offset del último nibble
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);

            // Convertir a código de 6 dígitos
            int otp = binary % (int)Math.Pow(10, DefaultDigits);
            return otp.ToString().PadLeft(DefaultDigits, '0');
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Security/PasswordHasher.cs
using AuthSystem.Core.Interfaces;
using System;

namespace AuthSystem.Infrastructure.Security
{
    public class PasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt(12));
        }

        public bool VerifyPassword(string passwordHash, string inputPassword)
        {
            return BCrypt.Net.BCrypt.Verify(inputPassword, passwordHash);
        }
    }
}

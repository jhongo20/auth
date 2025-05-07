using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando se intenta acceder a una cuenta bloqueada.
    /// </summary>
    public class AccountLockedException : DomainException
    {
        public string Username { get; }
        public DateTimeOffset? LockoutEnd { get; }

        public AccountLockedException(string username, DateTimeOffset? lockoutEnd = null)
            : base($"La cuenta para el usuario '{username}' está bloqueada{(lockoutEnd.HasValue ? $" hasta {lockoutEnd.Value.LocalDateTime}" : ".")}.")
        {
            Username = username;
            LockoutEnd = lockoutEnd;
        }
    }
}
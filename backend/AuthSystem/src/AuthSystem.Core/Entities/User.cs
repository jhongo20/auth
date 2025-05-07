using System;
using System.Collections.Generic;
using AuthSystem.Core.Enums; // Importamos el enum desde el espacio de nombres correcto

namespace AuthSystem.Core.Entities
{
    public class User
    {
        public Guid Id { get; private set; }
        public string Username { get; private set; }
        public string Email { get; private set; }
        public string PasswordHash { get; private set; }
        public string SecurityStamp { get; private set; }
        public string PhoneNumber { get; private set; }
        public bool PhoneNumberConfirmed { get; private set; }
        public bool TwoFactorEnabled { get; private set; }
        public DateTimeOffset? LockoutEnd { get; private set; }
        public bool LockoutEnabled { get; private set; }
        public int AccessFailedCount { get; private set; }
        public bool EmailConfirmed { get; private set; }
        public DateTime? LastLoginDate { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }
        public UserStatus Status { get; private set; } // Ahora usa el enum de Enums
        public DateTime? LastPasswordChangeDate { get; private set; }
        public bool RequirePasswordChange { get; private set; }
        public string ProfilePictureUrl { get; private set; }
        public string FirstName { get; private set; }
        public string LastName { get; private set; }
        public bool IsDeleted { get; private set; }
        public DateTime? DeletedAt { get; private set; }

        // Constructor privado para EF Core
        private User() { }

        // Constructor para crear un nuevo usuario
        public User(string username, string email, string passwordHash, string firstName = null, string lastName = null)
        {
            Id = Guid.NewGuid();
            Username = username;
            Email = email;
            PasswordHash = passwordHash;
            SecurityStamp = Guid.NewGuid().ToString();
            PhoneNumberConfirmed = false;
            TwoFactorEnabled = false;
            LockoutEnabled = true;
            AccessFailedCount = 0;
            EmailConfirmed = false;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
            Status = UserStatus.Registered;
            RequirePasswordChange = false;
            FirstName = firstName;
            LastName = lastName;
            IsDeleted = false;
        }

        // Métodos para actualizar propiedades
        public void UpdateProfile(string firstName, string lastName, string phoneNumber)
        {
            FirstName = firstName;
            LastName = lastName;
            PhoneNumber = phoneNumber;
            UpdatedAt = DateTime.UtcNow;
        }

        public void ConfirmEmail()
        {
            EmailConfirmed = true;
            if (Status == UserStatus.Registered)
            {
                Status = UserStatus.Active;
            }
            UpdatedAt = DateTime.UtcNow;
        }

        public void EnableTwoFactor()
        {
            TwoFactorEnabled = true;
            UpdatedAt = DateTime.UtcNow;
        }

        public void DisableTwoFactor()
        {
            TwoFactorEnabled = false;
            UpdatedAt = DateTime.UtcNow;
        }

        public void ChangePassword(string newPasswordHash)
        {
            PasswordHash = newPasswordHash;
            SecurityStamp = Guid.NewGuid().ToString();
            LastPasswordChangeDate = DateTime.UtcNow;
            RequirePasswordChange = false;
            UpdatedAt = DateTime.UtcNow;
        }

        public void ResetAccessFailedCount()
        {
            AccessFailedCount = 0;
            UpdatedAt = DateTime.UtcNow;
        }

        public void IncrementAccessFailedCount()
        {
            AccessFailedCount++;
            UpdatedAt = DateTime.UtcNow;
        }

        public void LockAccount(TimeSpan duration)
        {
            LockoutEnd = DateTimeOffset.UtcNow.Add(duration);
            Status = UserStatus.Blocked;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UnlockAccount()
        {
            LockoutEnd = null;
            Status = UserStatus.Active;
            AccessFailedCount = 0;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Delete()
        {
            IsDeleted = true;
            Status = UserStatus.Deleted;
            DeletedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UpdateLastLoginDate()
        {
            LastLoginDate = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Suspend()
        {
            Status = UserStatus.Suspended;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}
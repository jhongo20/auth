using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando una contraseña no cumple con las políticas de seguridad.
    /// </summary>
    public class PasswordPolicyException : DomainException
    {
        public IEnumerable<string> Errors { get; }

        public PasswordPolicyException(IEnumerable<string> errors)
            : base("La contraseña no cumple con las políticas de seguridad.")
        {
            Errors = errors;
        }

        public PasswordPolicyException(string message)
            : base(message)
        {
            Errors = new List<string> { message };
        }
    }
}
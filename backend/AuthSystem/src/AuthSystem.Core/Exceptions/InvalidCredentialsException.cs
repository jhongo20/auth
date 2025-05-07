using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando las credenciales de autenticación son inválidas.
    /// </summary>
    public class InvalidCredentialsException : DomainException
    {
        public InvalidCredentialsException()
            : base("Las credenciales proporcionadas son inválidas.") { }

        public InvalidCredentialsException(string message)
            : base(message) { }
    }
}
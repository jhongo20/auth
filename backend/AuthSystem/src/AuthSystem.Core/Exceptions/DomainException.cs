using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción base para todas las excepciones del dominio.
    /// </summary>
    public class DomainException : Exception
    {
        public DomainException() : base() { }

        public DomainException(string message) : base(message) { }

        public DomainException(string message, Exception innerException)
            : base(message, innerException) { }
    }
}
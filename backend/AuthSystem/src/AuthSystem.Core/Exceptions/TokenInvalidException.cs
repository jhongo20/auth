using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando un token es inválido o ha expirado.
    /// </summary>
    public class TokenInvalidException : DomainException
    {
        public string TokenType { get; }

        public TokenInvalidException(string tokenType)
            : base($"El token de {tokenType} es inválido o ha expirado.")
        {
            TokenType = tokenType;
        }

        public TokenInvalidException(string tokenType, string message)
            : base(message)
        {
            TokenType = tokenType;
        }
    }
}
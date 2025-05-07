using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando la validación de una entidad o comando falla.
    /// </summary>
    public class ValidationException : DomainException
    {
        public IDictionary<string, string[]> Errors { get; }

        public ValidationException(IDictionary<string, string[]> errors)
            : base("Se han producido uno o más errores de validación.")
        {
            Errors = errors;
        }

        public ValidationException(string propertyName, string error)
            : base($"Error de validación: {propertyName} - {error}")
        {
            Errors = new Dictionary<string, string[]>
            {
                { propertyName, new[] { error } }
            };
        }
    }
}
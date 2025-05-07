using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando un usuario no tiene permiso para realizar una acción.
    /// </summary>
    public class PermissionDeniedException : DomainException
    {
        public string Permission { get; }
        public string Username { get; }

        public PermissionDeniedException(string permission, string username)
            : base($"El usuario '{username}' no tiene el permiso '{permission}' requerido para esta operación.")
        {
            Permission = permission;
            Username = username;
        }

        public PermissionDeniedException(string message)
            : base(message) { }
    }
}
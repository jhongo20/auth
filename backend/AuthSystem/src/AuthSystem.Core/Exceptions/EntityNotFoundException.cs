using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando no se encuentra una entidad.
    /// </summary>
    public class EntityNotFoundException : DomainException
    {
        public string EntityName { get; }
        public object EntityId { get; }

        public EntityNotFoundException(string entityName, object entityId)
            : base($"La entidad '{entityName}' con id '{entityId}' no fue encontrada.")
        {
            EntityName = entityName;
            EntityId = entityId;
        }

        public EntityNotFoundException(string entityName, string message)
            : base(message)
        {
            EntityName = entityName;
        }
    }
}
using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando se intenta crear una entidad que ya existe.
    /// </summary>
    public class EntityAlreadyExistsException : DomainException
    {
        public string EntityName { get; }
        public string PropertyName { get; }
        public object PropertyValue { get; }

        public EntityAlreadyExistsException(string entityName, string propertyName, object propertyValue)
            : base($"Ya existe un/a {entityName} con {propertyName} '{propertyValue}'.")
        {
            EntityName = entityName;
            PropertyName = propertyName;
            PropertyValue = propertyValue;
        }
    }
}
using System;

namespace AuthSystem.Core.Entities
{
    public class Permission
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string Code { get; private set; }
        public string Description { get; private set; }
        public string Category { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Constructor privado para EF Core
        private Permission() { }

        // Constructor para crear un nuevo permiso
        public Permission(string name, string code, string description = null, string category = null)
        {
            Id = Guid.NewGuid();
            Name = name;
            Code = code;
            Description = description;
            Category = category;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        // Métodos para actualizar propiedades
        public void Update(string name, string code, string description, string category)
        {
            Name = name;
            Code = code;
            Description = description;
            Category = category;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}

using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Entities
{
    public class Role
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string NormalizedName { get; private set; }
        public string Description { get; private set; }
        public bool IsActive { get; private set; }
        public bool IsDefault { get; private set; }
        public int Priority { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Constructor privado para EF Core
        private Role() { }

        // Constructor para crear un nuevo rol
        public Role(string name, string description = null, bool isDefault = false, int priority = 0)
        {
            Id = Guid.NewGuid();
            Name = name;
            NormalizedName = name.ToUpperInvariant();
            Description = description;
            IsActive = true;
            IsDefault = isDefault;
            Priority = priority;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        // Métodos para actualizar propiedades
        public void Update(string name, string description, bool isActive, bool isDefault, int priority)
        {
            Name = name;
            NormalizedName = name.ToUpperInvariant();
            Description = description;
            IsActive = isActive;
            IsDefault = isDefault;
            Priority = priority;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Deactivate()
        {
            IsActive = false;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Activate()
        {
            IsActive = true;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}

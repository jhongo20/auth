using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Entities
{
    public class Module
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }
        public string Icon { get; private set; }
        public string Route { get; private set; }
        public bool IsActive { get; private set; }
        public int DisplayOrder { get; private set; }
        public Guid? ParentId { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Navegación
        public Module Parent { get; private set; }
        public ICollection<Module> Children { get; private set; }

        // Constructor privado para EF Core
        private Module() { }

        // Constructor para crear un nuevo módulo
        public Module(string name, string description = null, string icon = null, string route = null, 
                      int displayOrder = 0, Guid? parentId = null)
        {
            Id = Guid.NewGuid();
            Name = name;
            Description = description;
            Icon = icon;
            Route = route;
            IsActive = true;
            DisplayOrder = displayOrder;
            ParentId = parentId;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
            Children = new List<Module>();
        }

        // Métodos para actualizar propiedades
        public void Update(string name, string description, string icon, string route, 
                          bool isActive, int displayOrder, Guid? parentId)
        {
            Name = name;
            Description = description;
            Icon = icon;
            Route = route;
            IsActive = isActive;
            DisplayOrder = displayOrder;
            ParentId = parentId;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Activate()
        {
            IsActive = true;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Deactivate()
        {
            IsActive = false;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}

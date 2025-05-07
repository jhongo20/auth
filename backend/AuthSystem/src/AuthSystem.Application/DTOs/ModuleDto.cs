using System;
using System.Collections.Generic;

namespace AuthSystem.Application.DTOs
{
    public class ModuleDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Icon { get; set; }
        public string Route { get; set; }
        public bool IsActive { get; set; }
        public int DisplayOrder { get; set; }
        public Guid? ParentId { get; set; }
        public string ParentName { get; set; }
        public List<ModuleDto> Children { get; set; } = new List<ModuleDto>();
        public List<PermissionDto> Permissions { get; set; } = new List<PermissionDto>();
    }
}
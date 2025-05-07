using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthSystem.Core.Entities
{
    // Definición de entidades de relación
    public class UserRole
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public bool IsActive { get; set; }
    }

    public class RolePermission
    {
        public Guid RoleId { get; set; }
        public Guid PermissionId { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
    }

    public class UserPermission
    {
        public Guid UserId { get; set; }
        public Guid PermissionId { get; set; }
        public bool IsGranted { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
        public DateTime? ExpirationDate { get; set; }
    }

    public class ModulePermission
    {
        public Guid ModuleId { get; set; }
        public Guid PermissionId { get; set; }
    }

    // Clase base para entidades con campos de auditoría
    public abstract class BaseEntity
    {
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IRoleRepository : IRepository<Role>
    {
        Task<Role> FindByNameAsync(string name);
        Task<IReadOnlyList<Permission>> GetRolePermissionsAsync(Guid roleId);
        Task<bool> AddPermissionAsync(Guid roleId, Guid permissionId, Guid? assignedBy = null);
        Task<bool> RemovePermissionAsync(Guid roleId, Guid permissionId);
    }
}

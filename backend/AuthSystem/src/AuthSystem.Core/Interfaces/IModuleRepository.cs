using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IModuleRepository : IRepository<Module>
    {
        Task<IReadOnlyList<Module>> GetRootModulesAsync();
        Task<IReadOnlyList<Module>> GetChildModulesAsync(Guid parentId);
        Task<IReadOnlyList<Module>> GetUserModulesAsync(Guid userId);
        Task<bool> AddModulePermissionAsync(Guid moduleId, Guid permissionId);
        Task<bool> RemoveModulePermissionAsync(Guid moduleId, Guid permissionId);
        Task<IReadOnlyList<Permission>> GetModulePermissionsAsync(Guid moduleId);
    }
}

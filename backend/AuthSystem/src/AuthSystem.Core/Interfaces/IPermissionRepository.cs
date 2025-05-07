using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IPermissionRepository : IRepository<Permission>
    {
        Task<Permission> FindByCodeAsync(string code);
        Task<IReadOnlyList<Permission>> GetByCategoryAsync(string category);
    }
}

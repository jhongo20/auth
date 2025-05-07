using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Repositories/RoleRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class RoleRepository : Repository<Role>, IRoleRepository
    {
        public RoleRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<Role> FindByNameAsync(string name)
        {
            return await _dbSet.FirstOrDefaultAsync(r => r.Name == name || r.NormalizedName == name.ToUpperInvariant());
        }

        public async Task<IReadOnlyList<Permission>> GetRolePermissionsAsync(Guid roleId)
        {
            var permissionIds = await _context.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .Select(rp => rp.PermissionId)
                .ToListAsync();

            return await _context.Permissions
                .Where(p => permissionIds.Contains(p.Id))
                .ToListAsync();
        }

        public async Task<bool> AddPermissionAsync(Guid roleId, Guid permissionId, Guid? assignedBy = null)
        {
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

            if (rolePermission != null)
            {
                return true; // Ya existe, no es necesario hacer nada
            }

            rolePermission = new RolePermission
            {
                RoleId = roleId,
                PermissionId = permissionId,
                AssignedBy = assignedBy,
                AssignedAt = DateTime.UtcNow
            };

            await _context.RolePermissions.AddAsync(rolePermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemovePermissionAsync(Guid roleId, Guid permissionId)
        {
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

            if (rolePermission == null)
            {
                return false;
            }

            _context.RolePermissions.Remove(rolePermission);
            return await _context.SaveChangesAsync() > 0;
        }
    }
}

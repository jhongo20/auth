using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Repositories/ModuleRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class ModuleRepository : Repository<Module>, IModuleRepository
    {
        public ModuleRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<IReadOnlyList<Module>> GetRootModulesAsync()
        {
            return await _dbSet.Where(m => m.ParentId == null && m.IsActive)
                .OrderBy(m => m.DisplayOrder)
                .ToListAsync();
        }

        public async Task<IReadOnlyList<Module>> GetChildModulesAsync(Guid parentId)
        {
            return await _dbSet.Where(m => m.ParentId == parentId && m.IsActive)
                .OrderBy(m => m.DisplayOrder)
                .ToListAsync();
        }

        public async Task<IReadOnlyList<Module>> GetUserModulesAsync(Guid userId)
        {
            // Podríamos llamar directamente al procedimiento almacenado
            // Pero aquí mostraremos la implementación equivalente con EF Core

            // Obtener todos los permisos del usuario
            var userPermissions = new List<Guid>();

            // Permisos directos
            var directPermissions = await _context.UserPermissions
                .Where(up => up.UserId == userId && up.IsGranted)
                .Where(up => up.ExpirationDate == null || up.ExpirationDate > DateTime.UtcNow)
                .Select(up => up.PermissionId)
                .ToListAsync();

            userPermissions.AddRange(directPermissions);

            // Permisos basados en roles
            var rolePermissions = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.IsActive)
                .Where(ur => ur.ExpirationDate == null || ur.ExpirationDate > DateTime.UtcNow)
                .Join(_context.RolePermissions,
                    ur => ur.RoleId,
                    rp => rp.RoleId,
                    (ur, rp) => rp.PermissionId)
                .Distinct()
                .ToListAsync();

            userPermissions.AddRange(rolePermissions);
            userPermissions = userPermissions.Distinct().ToList();

            // Obtener módulos accesibles
            var moduleIds = await _context.ModulePermissions
                .Where(mp => userPermissions.Contains(mp.PermissionId))
                .Select(mp => mp.ModuleId)
                .Distinct()
                .ToListAsync();

            return await _dbSet
                .Where(m => moduleIds.Contains(m.Id) && m.IsActive)
                .OrderBy(m => m.ParentId)
                .ThenBy(m => m.DisplayOrder)
                .ToListAsync();
        }

        public async Task<bool> AddModulePermissionAsync(Guid moduleId, Guid permissionId)
        {
            var modulePermission = await _context.ModulePermissions
                .FirstOrDefaultAsync(mp => mp.ModuleId == moduleId && mp.PermissionId == permissionId);

            if (modulePermission != null)
            {
                return true; // Ya existe, no es necesario hacer nada
            }

            modulePermission = new ModulePermission
            {
                ModuleId = moduleId,
                PermissionId = permissionId
            };

            await _context.ModulePermissions.AddAsync(modulePermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveModulePermissionAsync(Guid moduleId, Guid permissionId)
        {
            var modulePermission = await _context.ModulePermissions
                .FirstOrDefaultAsync(mp => mp.ModuleId == moduleId && mp.PermissionId == permissionId);

            if (modulePermission == null)
            {
                return false;
            }

            _context.ModulePermissions.Remove(modulePermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<IReadOnlyList<Permission>> GetModulePermissionsAsync(Guid moduleId)
        {
            var permissionIds = await _context.ModulePermissions
                .Where(mp => mp.ModuleId == moduleId)
                .Select(mp => mp.PermissionId)
                .ToListAsync();

            return await _context.Permissions
                .Where(p => permissionIds.Contains(p.Id))
                .ToListAsync();
        }
    }
}

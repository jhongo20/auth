using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Repositories/PermissionRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class PermissionRepository : Repository<Permission>, IPermissionRepository
    {
        public PermissionRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<Permission> FindByCodeAsync(string code)
        {
            return await _dbSet.FirstOrDefaultAsync(p => p.Code == code);
        }

        public async Task<IReadOnlyList<Permission>> GetByCategoryAsync(string category)
        {
            return await _dbSet.Where(p => p.Category == category).ToListAsync();
        }
    }
}

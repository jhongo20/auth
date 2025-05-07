using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Repositories/AuditRepository.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class AuditRepository : IAuditRepository
    {
        private readonly ApplicationDbContext _context;

        public AuditRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task LogActionAsync(Guid? userId, string action, string entityName, string entityId,
                                        string oldValues, string newValues, string ipAddress, string userAgent)
        {
            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Action = action,
                EntityName = entityName,
                EntityId = entityId,
                OldValues = oldValues,
                NewValues = newValues,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                CreatedAt = DateTime.UtcNow
            };

            await _context.AuditLog.AddAsync(auditLog);
            await _context.SaveChangesAsync();
        }

        public async Task LogLoginAttemptAsync(string username, string email, string ipAddress, string userAgent,
                                              bool successful, string failureReason, Guid? userId)
        {
            var loginAttempt = new LoginAttempt
            {
                Id = Guid.NewGuid(),
                Username = username,
                Email = email,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                Successful = successful,
                FailureReason = failureReason,
                AttemptedAt = DateTime.UtcNow,
                UserId = userId
            };

            await _context.LoginAttempts.AddAsync(loginAttempt);
            await _context.SaveChangesAsync();
        }

        public async Task<IReadOnlyList<AuditLog>> GetAuditLogsAsync(DateTime? startDate, DateTime? endDate,
                                                                     Guid? userId, string entityName, string action)
        {
            var query = _context.AuditLog.AsQueryable();

            if (startDate.HasValue)
            {
                query = query.Where(a => a.CreatedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(a => a.CreatedAt <= endDate.Value);
            }

            if (userId.HasValue)
            {
                query = query.Where(a => a.UserId == userId.Value);
            }

            if (!string.IsNullOrEmpty(entityName))
            {
                query = query.Where(a => a.EntityName == entityName);
            }

            if (!string.IsNullOrEmpty(action))
            {
                query = query.Where(a => a.Action == action);
            }

            return await query.OrderByDescending(a => a.CreatedAt).ToListAsync();
        }

        public async Task<IReadOnlyList<LoginAttempt>> GetLoginAttemptsAsync(DateTime? startDate, DateTime? endDate,
                                                                             Guid? userId, string ipAddress, bool? successful)
        {
            var query = _context.LoginAttempts.AsQueryable();

            if (startDate.HasValue)
            {
                query = query.Where(la => la.AttemptedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(la => la.AttemptedAt <= endDate.Value);
            }

            if (userId.HasValue)
            {
                query = query.Where(la => la.UserId == userId.Value);
            }

            if (!string.IsNullOrEmpty(ipAddress))
            {
                query = query.Where(la => la.IPAddress == ipAddress);
            }

            if (successful.HasValue)
            {
                query = query.Where(la => la.Successful == successful.Value);
            }

            return await query.OrderByDescending(la => la.AttemptedAt).ToListAsync();
        }
    }
}

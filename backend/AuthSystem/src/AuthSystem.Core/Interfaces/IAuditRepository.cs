using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IAuditRepository
    {
        Task LogActionAsync(Guid? userId, string action, string entityName, string entityId, 
                           string oldValues, string newValues, string ipAddress, string userAgent);
        Task LogLoginAttemptAsync(string username, string email, string ipAddress, string userAgent,
                                 bool successful, string failureReason, Guid? userId);
        Task<IReadOnlyList<AuditLog>> GetAuditLogsAsync(DateTime? startDate, DateTime? endDate, 
                                                      Guid? userId, string entityName, string action);
        Task<IReadOnlyList<LoginAttempt>> GetLoginAttemptsAsync(DateTime? startDate, DateTime? endDate, 
                                                               Guid? userId, string ipAddress, bool? successful);
    }
}

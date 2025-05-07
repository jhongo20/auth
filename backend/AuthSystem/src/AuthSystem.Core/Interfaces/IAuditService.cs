using System;
using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IAuditService
    {
        Task LogActionAsync(Guid? userId, string action, string entityName, string entityId, 
                           object oldValues, object newValues, string ipAddress = null, string userAgent = null);
        Task LogLoginAttemptAsync(string username, string ipAddress, string userAgent, 
                                 bool successful, string failureReason = null, Guid? userId = null);
    }
}

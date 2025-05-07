using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Services/AuditService.cs
using System;
using System.Text.Json;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;

namespace AuthSystem.Infrastructure.Services
{
    public class AuditService : IAuditService
    {
        private readonly IAuditRepository _auditRepository;

        public AuditService(IAuditRepository auditRepository)
        {
            _auditRepository = auditRepository;
        }

        public async Task LogActionAsync(Guid? userId, string action, string entityName, string entityId,
                                        object oldValues, object newValues, string ipAddress = null, string userAgent = null)
        {
            string oldValuesJson = oldValues != null ? JsonSerializer.Serialize(oldValues) : null;
            string newValuesJson = newValues != null ? JsonSerializer.Serialize(newValues) : null;

            await _auditRepository.LogActionAsync(userId, action, entityName, entityId,
                                                oldValuesJson, newValuesJson, ipAddress, userAgent);
        }

        public async Task LogLoginAttemptAsync(string username, string ipAddress, string userAgent,
                                              bool successful, string failureReason = null, Guid? userId = null)
        {
            string email = null;

            // Verificar si username es un email
            if (username != null && username.Contains("@"))
            {
                email = username;
            }

            await _auditRepository.LogLoginAttemptAsync(username, email, ipAddress, userAgent,
                                                      successful, failureReason, userId);
        }
    }
}

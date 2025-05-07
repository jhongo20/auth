using System;

namespace AuthSystem.Application.DTOs
{
    public class AuditLogDto
    {
        public Guid Id { get; set; }
        public Guid? UserId { get; set; }
        public string Username { get; set; }
        public string Action { get; set; }
        public string EntityName { get; set; }
        public string EntityId { get; set; }
        public string IPAddress { get; set; }
        public DateTime CreatedAt { get; set; }
        public object Details { get; set; }
    }
}
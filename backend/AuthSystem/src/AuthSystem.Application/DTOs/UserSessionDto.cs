using System;

namespace AuthSystem.Application.DTOs
{
    public class UserSessionDto
    {
        public Guid Id { get; set; }
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
        public string DeviceInfo { get; set; }
        public DateTime IssuedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsCurrentSession { get; set; }
        public bool IsActive { get; set; }
    }
}
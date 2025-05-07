namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Tipos de claims personalizados utilizados en JWT.
    /// </summary>
    public static class ClaimTypes
    {
        public const string Permission = "permission";
        public const string FullName = "full_name";
        public const string UserId = "user_id";
        public const string TenantId = "tenant_id";
        public const string UserStatus = "user_status";
        public const string TwoFactorEnabled = "2fa_enabled";
        public const string LastPasswordChange = "last_pwd_change";
        public const string SessionId = "session_id";
    }
}
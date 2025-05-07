namespace AuthSystem.Core.Enums
{
    public enum AuditActionType
    {
        Create = 1,
        Read = 2,
        Update = 3,
        Delete = 4,
        Login = 5,
        Logout = 6,
        FailedLogin = 7,
        PasswordChange = 8,
        PasswordReset = 9,
        EmailChange = 10,
        RoleAssigned = 11,
        RoleRemoved = 12,
        PermissionGranted = 13,
        PermissionRevoked = 14,
        AccountLocked = 15,
        AccountUnlocked = 16,
        TwoFactorEnabled = 17,
        TwoFactorDisabled = 18,
        Export = 19,
        Import = 20,
        SystemError = 21,
        Other = 99
    }
}
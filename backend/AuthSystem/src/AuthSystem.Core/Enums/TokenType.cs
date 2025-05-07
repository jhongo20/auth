namespace AuthSystem.Core.Enums
{
    public enum TokenType
    {
        Access = 1,
        Refresh = 2,
        EmailConfirmation = 3,
        PasswordReset = 4,
        TwoFactorAuthentication = 5,
        InvitationToken = 6
    }
}
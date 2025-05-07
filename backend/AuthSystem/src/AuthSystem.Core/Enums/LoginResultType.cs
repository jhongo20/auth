namespace AuthSystem.Core.Enums
{
    public enum LoginResultType
    {
        Success = 1,
        InvalidCredentials = 2,
        AccountLocked = 3,
        AccountDisabled = 4,
        AccountNotActivated = 5,
        RequiresTwoFactor = 6,
        RequiresPasswordChange = 7,
        TooManyAttempts = 8,
        AccountDeleted = 9,
        RecaptchaFailed = 10,
        SystemError = 99
    }
}
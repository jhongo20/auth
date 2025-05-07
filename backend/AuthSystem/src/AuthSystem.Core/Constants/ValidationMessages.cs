namespace AuthSystem.Core.Constants
{
    /// <summary>
    /// Mensajes estándar para validaciones.
    /// </summary>
    public static class ValidationMessages
    {
        // Mensajes genéricos
        public const string Required = "El campo {0} es obligatorio.";
        public const string InvalidFormat = "El campo {0} tiene un formato inválido.";
        public const string MaxLength = "El campo {0} no debe exceder {1} caracteres.";
        public const string MinLength = "El campo {0} debe tener al menos {1} caracteres.";
        public const string Range = "El campo {0} debe estar entre {1} y {2}.";
        public const string Equal = "El campo {0} debe ser igual a {1}.";
        public const string NotEqual = "El campo {0} no debe ser igual a {1}.";
        public const string InvalidEnum = "El valor seleccionado para {0} es inválido.";

        // Mensajes específicos
        public const string InvalidEmail = "El correo electrónico proporcionado no es válido.";
        public const string PasswordRequiresDigit = "La contraseña debe contener al menos un dígito.";
        public const string PasswordRequiresLower = "La contraseña debe contener al menos una letra minúscula.";
        public const string PasswordRequiresUpper = "La contraseña debe contener al menos una letra mayúscula.";
        public const string PasswordRequiresNonAlphanumeric = "La contraseña debe contener al menos un carácter especial.";
        public const string PasswordsDoNotMatch = "Las contraseñas no coinciden.";
        public const string InvalidUsername = "El nombre de usuario solo puede contener letras, números, guiones y guiones bajos.";
        public const string EntityExists = "Ya existe un/a {0} con este {1}.";
        public const string EntityNotFound = "No se encontró el/la {0} especificado/a.";
        public const string InvalidCredentials = "Las credenciales proporcionadas son inválidas.";
        public const string AccountLocked = "Su cuenta está temporalmente bloqueada. Intente nuevamente más tarde.";
        public const string EmailNotConfirmed = "Debe confirmar su correo electrónico antes de iniciar sesión.";
        public const string TwoFactorCodeInvalid = "El código de verificación es inválido.";
        public const string RecaptchaFailed = "La verificación de seguridad ha fallado. Por favor, inténtelo de nuevo.";
    }
}
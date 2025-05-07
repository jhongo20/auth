using System;

namespace AuthSystem.Core.Exceptions
{
    /// <summary>
    /// Excepción lanzada cuando se requiere autenticación de dos factores.
    /// </summary>
    public class TwoFactorRequiredException : DomainException
    {
        public Guid UserId { get; }
        public string TwoFactorMethod { get; }

        public TwoFactorRequiredException(Guid userId, string twoFactorMethod)
            : base("Se requiere autenticación de dos factores para continuar.")
        {
            UserId = userId;
            TwoFactorMethod = twoFactorMethod;
        }
    }
}
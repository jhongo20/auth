namespace AuthSystem.Core.Enums
{
    public enum UserStatus
    {
        Registered = 1,   // Usuario recién registrado, pendiente de activación
        Active = 2,       // Usuario activo y funcional
        Blocked = 3,      // Usuario bloqueado temporalmente
        Suspended = 4,    // Usuario suspendido por razones administrativas 
        Deleted = 5       // Usuario marcado como eliminado (borrado lógico)
    }
}
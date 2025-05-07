namespace AuthSystem.Core.Enums
{
    public enum RoleType
    {
        SuperAdmin = 1,   // Acceso completo a todo el sistema
        Admin = 2,        // Administrador con acceso a la mayoría de funciones
        Manager = 3,      // Puede gestionar usuarios y algunas configuraciones
        Supervisor = 4,   // Supervisa actividades pero con acceso limitado
        User = 5,         // Usuario estándar con funcionalidades básicas
        ReadOnly = 6,     // Usuario con acceso de solo lectura
        Guest = 7         // Acceso mínimo para usuarios no registrados o visitantes
    }
}
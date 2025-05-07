namespace AuthSystem.Core.Enums
{
    public enum PermissionType
    {
        // Permisos generales
        View = 100,
        Create = 101,
        Edit = 102,
        Delete = 103,
        Export = 104,
        Import = 105,

        // Permisos específicos para usuarios
        ManageUsers = 200,
        ViewUsers = 201,
        CreateUsers = 202,
        EditUsers = 203,
        DeleteUsers = 204,

        // Permisos para roles
        ManageRoles = 300,
        ViewRoles = 301,
        CreateRoles = 302,
        EditRoles = 303,
        DeleteRoles = 304,

        // Permisos para módulos
        ManageModules = 400,
        ViewModules = 401,

        // Permisos para configuración del sistema
        ManageSettings = 500,
        ViewSettings = 501,

        // Permisos para auditoría
        ViewAuditLogs = 600,
        ExportAuditLogs = 601
    }
}
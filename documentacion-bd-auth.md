# Documentación Base de Datos Auth

## Tabla de Contenidos
1. [Introducción](#introducción)
2. [Diagrama Entidad-Relación](#diagrama-entidad-relación)
3. [Catálogo de Tablas](#catálogo-de-tablas)
   - [Users](#users)
   - [Roles](#roles)
   - [UserRoles](#userroles)
   - [Permissions](#permissions)
   - [RolePermissions](#rolepermissions)
   - [UserPermissions](#userpermissions)
   - [Modules](#modules)
   - [ModulePermissions](#modulepermissions)
   - [LoginAttempts](#loginattempts)
   - [AuditLog](#auditlog)
   - [UserSessions](#usersessions)
   - [UserTwoFactorSettings](#usertwofactorsettings)
   - [PasswordHistory](#passwordhistory)
4. [Índices](#índices)
5. [Procedimientos Almacenados](#procedimientos-almacenados)
6. [Diseño de Seguridad](#diseño-de-seguridad)
7. [Mantenimiento](#mantenimiento)

## Introducción

La base de datos Auth es un sistema completo para la gestión de autenticación, autorización, y auditoría de usuarios. Diseñada para aplicaciones empresariales seguras y escalables, proporciona funcionalidades como:

- Gestión de usuarios con múltiples estados
- Sistema de roles y permisos granular
- Autenticación multi-factor
- Registro completo de auditoría
- Gestión de sesiones
- Historial de contraseñas
- Modularización de aplicaciones basada en permisos

Esta documentación detalla cada componente del esquema de la base de datos y sus relaciones.

## Diagrama Entidad-Relación

*Nota: Insertar diagrama ER aquí*

## Catálogo de Tablas

### Users

Almacena información de los usuarios del sistema.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| Username | NVARCHAR(100) | No | Nombre de usuario único |
| Email | NVARCHAR(255) | No | Correo electrónico único |
| NormalizedEmail | NVARCHAR(255) | No | Correo electrónico normalizado para búsquedas |
| PasswordHash | NVARCHAR(MAX) | No | Hash de contraseña |
| SecurityStamp | NVARCHAR(MAX) | No | Estampa de seguridad para invalidación |
| ConcurrencyStamp | NVARCHAR(MAX) | Sí | Estampa para control de concurrencia |
| PhoneNumber | NVARCHAR(20) | Sí | Número telefónico |
| PhoneNumberConfirmed | BIT | No | Indica si el teléfono está confirmado |
| TwoFactorEnabled | BIT | No | Indica si 2FA está activo |
| LockoutEnd | DATETIMEOFFSET | Sí | Fecha fin de bloqueo |
| LockoutEnabled | BIT | No | Indica si el bloqueo está habilitado |
| AccessFailedCount | INT | No | Contador de intentos fallidos |
| EmailConfirmed | BIT | No | Indica si el correo está confirmado |
| LastLoginDate | DATETIME2 | Sí | Fecha del último inicio de sesión |
| CreatedAt | DATETIME2 | No | Fecha de creación |
| UpdatedAt | DATETIME2 | No | Fecha de última actualización |
| UserStatus | INT | No | Estado del usuario (1=Registrado, 2=Activo, 3=Bloqueado, 4=Eliminado) |
| LastPasswordChangeDate | DATETIME2 | Sí | Fecha del último cambio de contraseña |
| RequirePasswordChange | BIT | No | Indica si se requiere cambio de contraseña |
| PasswordResetToken | NVARCHAR(MAX) | Sí | Token para restablecimiento de contraseña |
| PasswordResetTokenExpiry | DATETIME2 | Sí | Expiración del token de restablecimiento |
| ProfilePictureUrl | NVARCHAR(MAX) | Sí | URL de imagen de perfil |
| FirstName | NVARCHAR(100) | Sí | Nombre |
| LastName | NVARCHAR(100) | Sí | Apellido |
| IsDeleted | BIT | No | Indica borrado lógico |
| DeletedAt | DATETIME2 | Sí | Fecha de borrado lógico |

### Roles

Define roles que pueden asignarse a usuarios.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| Name | NVARCHAR(100) | No | Nombre del rol único |
| NormalizedName | NVARCHAR(100) | No | Nombre normalizado para búsquedas |
| Description | NVARCHAR(255) | Sí | Descripción del rol |
| IsActive | BIT | No | Indica si el rol está activo |
| IsDefault | BIT | No | Indica si es rol por defecto |
| Priority | INT | No | Prioridad para resolución de conflictos |
| CreatedAt | DATETIME2 | No | Fecha de creación |
| UpdatedAt | DATETIME2 | No | Fecha de última actualización |

### UserRoles

Tabla de relación entre usuarios y roles.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| UserId | UNIQUEIDENTIFIER | No | ID del usuario (PK, FK) |
| RoleId | UNIQUEIDENTIFIER | No | ID del rol (PK, FK) |
| AssignedBy | UNIQUEIDENTIFIER | Sí | ID del usuario que asignó el rol |
| AssignedAt | DATETIME2 | No | Fecha de asignación |
| ExpirationDate | DATETIME2 | Sí | Fecha de expiración del rol |
| IsActive | BIT | No | Indica si la asignación está activa |

### Permissions

Define permisos granulares que pueden asignarse a roles o usuarios.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| Name | NVARCHAR(100) | No | Nombre descriptivo |
| Code | NVARCHAR(100) | No | Código único para referencias |
| Description | NVARCHAR(255) | Sí | Descripción del permiso |
| Category | NVARCHAR(100) | Sí | Categoría para agrupar |
| CreatedAt | DATETIME2 | No | Fecha de creación |
| UpdatedAt | DATETIME2 | No | Fecha de última actualización |

### RolePermissions

Tabla de relación entre roles y permisos.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| RoleId | UNIQUEIDENTIFIER | No | ID del rol (PK, FK) |
| PermissionId | UNIQUEIDENTIFIER | No | ID del permiso (PK, FK) |
| AssignedBy | UNIQUEIDENTIFIER | Sí | ID del usuario que asignó el permiso |
| AssignedAt | DATETIME2 | No | Fecha de asignación |

### UserPermissions

Permisos específicos asignados a usuarios (sobrescribe roles).

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| UserId | UNIQUEIDENTIFIER | No | ID del usuario (PK, FK) |
| PermissionId | UNIQUEIDENTIFIER | No | ID del permiso (PK, FK) |
| IsGranted | BIT | No | Indica si el permiso está concedido |
| AssignedBy | UNIQUEIDENTIFIER | Sí | ID del usuario que asignó el permiso |
| AssignedAt | DATETIME2 | No | Fecha de asignación |
| ExpirationDate | DATETIME2 | Sí | Fecha de expiración del permiso |

### Modules

Define módulos o secciones de la aplicación que requieren permisos.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| Name | NVARCHAR(100) | No | Nombre del módulo |
| Description | NVARCHAR(255) | Sí | Descripción del módulo |
| Icon | NVARCHAR(100) | Sí | Icono para UI |
| Route | NVARCHAR(100) | Sí | Ruta de navegación |
| IsActive | BIT | No | Indica si está activo |
| DisplayOrder | INT | No | Orden de visualización |
| ParentId | UNIQUEIDENTIFIER | Sí | ID del módulo padre (FK) |
| CreatedAt | DATETIME2 | No | Fecha de creación |
| UpdatedAt | DATETIME2 | No | Fecha de última actualización |

### ModulePermissions

Permisos requeridos para acceder a módulos.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| ModuleId | UNIQUEIDENTIFIER | No | ID del módulo (PK, FK) |
| PermissionId | UNIQUEIDENTIFIER | No | ID del permiso (PK, FK) |

### LoginAttempts

Registro de intentos de inicio de sesión.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| Username | NVARCHAR(100) | No | Nombre de usuario intentado |
| Email | NVARCHAR(255) | Sí | Correo electrónico intentado |
| IPAddress | NVARCHAR(50) | No | Dirección IP |
| UserAgent | NVARCHAR(MAX) | Sí | Agente de usuario |
| Successful | BIT | No | Indica si el intento fue exitoso |
| FailureReason | NVARCHAR(255) | Sí | Razón de fallo |
| AttemptedAt | DATETIME2 | No | Fecha y hora del intento |
| UserId | UNIQUEIDENTIFIER | Sí | ID del usuario (FK) |

### AuditLog

Registro de auditoría de todas las operaciones.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| UserId | UNIQUEIDENTIFIER | Sí | ID del usuario (FK) |
| Action | NVARCHAR(100) | No | Acción realizada |
| EntityName | NVARCHAR(100) | No | Entidad afectada |
| EntityId | NVARCHAR(100) | Sí | Identificador de la entidad |
| OldValues | NVARCHAR(MAX) | Sí | Valores anteriores (JSON) |
| NewValues | NVARCHAR(MAX) | Sí | Valores nuevos (JSON) |
| IPAddress | NVARCHAR(50) | Sí | Dirección IP |
| UserAgent | NVARCHAR(MAX) | Sí | Agente de usuario |
| CreatedAt | DATETIME2 | No | Fecha y hora del evento |

### UserSessions

Registro de sesiones de usuario activas.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| UserId | UNIQUEIDENTIFIER | No | ID del usuario (FK) |
| Token | NVARCHAR(MAX) | No | Token JWT |
| RefreshToken | NVARCHAR(MAX) | Sí | Token de actualización |
| IPAddress | NVARCHAR(50) | No | Dirección IP |
| UserAgent | NVARCHAR(MAX) | Sí | Agente de usuario |
| DeviceInfo | NVARCHAR(MAX) | Sí | Información del dispositivo |
| IssuedAt | DATETIME2 | No | Fecha de emisión |
| ExpiresAt | DATETIME2 | No | Fecha de expiración |
| RevokedAt | DATETIME2 | Sí | Fecha de revocación |
| IsActive | AS (CASE WHEN [RevokedAt] IS NULL AND [ExpiresAt] > GETUTCDATE() THEN 1 ELSE 0 END) | N/A | Columna calculada que indica si la sesión está activa |

> **Nota de mejora:** Se corrigió el nombre de la columna de `RevSEX` a `RevokedAt` para mantener coherencia en la nomenclatura y permitir el correcto funcionamiento de la columna calculada `IsActive` que determina si una sesión sigue activa comparando la fecha de expiración con la fecha actual y verificando si la sesión ha sido revocada.

### UserTwoFactorSettings

Configuraciones de autenticación de dos factores.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| UserId | UNIQUEIDENTIFIER | No | ID del usuario (PK, FK) |
| IsEnabled | BIT | No | Indica si 2FA está habilitado |
| Method | NVARCHAR(50) | No | Método de 2FA (Email, SMS, Authenticator) |
| SecretKey | NVARCHAR(MAX) | Sí | Clave secreta para apps autenticadoras |
| RecoveryCodesJson | NVARCHAR(MAX) | Sí | Códigos de recuperación (JSON) |
| UpdatedAt | DATETIME2 | No | Fecha de última actualización |

### PasswordHistory

Historial de contraseñas para prevenir reutilización.

| Columna | Tipo | Nulo | Descripción |
|---------|------|------|-------------|
| Id | UNIQUEIDENTIFIER | No | Identificador único (PK) |
| UserId | UNIQUEIDENTIFIER | No | ID del usuario (FK) |
| PasswordHash | NVARCHAR(MAX) | No | Hash de contraseña anterior |
| ChangedAt | DATETIME2 | No | Fecha de cambio |
| IPAddress | NVARCHAR(50) | Sí | Dirección IP |
| UserAgent | NVARCHAR(MAX) | Sí | Agente de usuario |

## Índices

La base de datos incluye los siguientes índices para optimizar el rendimiento:

```sql
-- Índices para búsqueda rápida de usuarios
CREATE NONCLUSTERED INDEX [IX_Users_Email] ON [dbo].[Users] ([Email]);
CREATE NONCLUSTERED INDEX [IX_Users_Username] ON [dbo].[Users] ([Username]);
CREATE NONCLUSTERED INDEX [IX_Users_UserStatus] ON [dbo].[Users] ([UserStatus]);

-- Índices para auditoría
CREATE NONCLUSTERED INDEX [IX_AuditLog_UserId] ON [dbo].[AuditLog] ([UserId]);
CREATE NONCLUSTERED INDEX [IX_AuditLog_EntityName_EntityId] ON [dbo].[AuditLog] ([EntityName], [EntityId]);
CREATE NONCLUSTERED INDEX [IX_AuditLog_CreatedAt] ON [dbo].[AuditLog] ([CreatedAt]);

-- Índices para sesiones
CREATE NONCLUSTERED INDEX [IX_UserSessions_UserId] ON [dbo].[UserSessions] ([UserId]);
CREATE NONCLUSTERED INDEX [IX_UserSessions_ExpiresAt] ON [dbo].[UserSessions] ([ExpiresAt]);

-- Índices para intentos de login
CREATE NONCLUSTERED INDEX [IX_LoginAttempts_Username] ON [dbo].[LoginAttempts] ([Username]);
CREATE NONCLUSTERED INDEX [IX_LoginAttempts_IPAddress] ON [dbo].[LoginAttempts] ([IPAddress]);
CREATE NONCLUSTERED INDEX [IX_LoginAttempts_AttemptedAt] ON [dbo].[LoginAttempts] ([AttemptedAt]);

-- Índices para módulos
CREATE NONCLUSTERED INDEX [IX_Modules_ParentId] ON [dbo].[Modules] ([ParentId]);
```

## Procedimientos Almacenados

### GetUserPermissions

Recupera todos los permisos de un usuario, incluyendo los directos y los derivados de roles.

```sql
CREATE PROCEDURE [dbo].[GetUserPermissions]
    @UserId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Permisos directos de usuario
    SELECT p.Id, p.Name, p.Code, p.Description, p.Category, 'Direct' AS Source
    FROM [dbo].[Permissions] p
    INNER JOIN [dbo].[UserPermissions] up ON p.Id = up.PermissionId
    WHERE up.UserId = @UserId AND up.IsGranted = 1
        AND (up.ExpirationDate IS NULL OR up.ExpirationDate > GETUTCDATE())
    
    UNION
    
    -- Permisos basados en roles
    SELECT p.Id, p.Name, p.Code, p.Description, p.Category, r.Name AS Source
    FROM [dbo].[Permissions] p
    INNER JOIN [dbo].[RolePermissions] rp ON p.Id = rp.PermissionId
    INNER JOIN [dbo].[Roles] r ON rp.RoleId = r.Id
    INNER JOIN [dbo].[UserRoles] ur ON r.Id = ur.RoleId
    WHERE ur.UserId = @UserId AND ur.IsActive = 1 AND r.IsActive = 1
        AND (ur.ExpirationDate IS NULL OR ur.ExpirationDate > GETUTCDATE())
END
```

### GetUserModules

Recupera todos los módulos a los que un usuario tiene acceso basado en sus permisos.

```sql
CREATE PROCEDURE [dbo].[GetUserModules]
    @UserId UNIQUEIDENTIFIER
AS
BEGIN
    SET NOCOUNT ON;
    
    -- Obtener todos los permisos del usuario
    DECLARE @UserPermissions TABLE (PermissionId UNIQUEIDENTIFIER);
    
    -- Permisos directos
    INSERT INTO @UserPermissions
    SELECT PermissionId
    FROM [dbo].[UserPermissions]
    WHERE UserId = @UserId AND IsGranted = 1
        AND (ExpirationDate IS NULL OR ExpirationDate > GETUTCDATE());
    
    -- Permisos basados en roles
    INSERT INTO @UserPermissions
    SELECT rp.PermissionId
    FROM [dbo].[RolePermissions] rp
    INNER JOIN [dbo].[UserRoles] ur ON rp.RoleId = ur.RoleId
    WHERE ur.UserId = @UserId AND ur.IsActive = 1
        AND (ur.ExpirationDate IS NULL OR ur.ExpirationDate > GETUTCDATE());
    
    -- Obtener módulos accesibles
    SELECT DISTINCT m.*
    FROM [dbo].[Modules] m
    INNER JOIN [dbo].[ModulePermissions] mp ON m.Id = mp.ModuleId
    WHERE mp.PermissionId IN (SELECT PermissionId FROM @UserPermissions)
      AND m.IsActive = 1
    ORDER BY m.ParentId, m.DisplayOrder;
END
```

## Diseño de Seguridad

La base de datos ha sido diseñada siguiendo principios de seguridad por defecto:

1. **Almacenamiento seguro de contraseñas**: Las contraseñas se almacenan como hashes criptográficos.
2. **Auditoría completa**: Todas las acciones relevantes se registran en AuditLog.
3. **Bloqueo de cuentas**: Mecanismo automático de bloqueo tras intentos fallidos.
4. **Políticas de reutilización**: El historial de contraseñas previene su reutilización.
5. **Revocación de sesiones**: Capacidad para revocar sesiones activas.
6. **Permisos granulares**: Sistema de permisos detallado y flexible.
7. **Borrado lógico**: Los usuarios nunca se eliminan físicamente.
8. **Validez temporal**: Roles y permisos pueden tener fechas de expiración.

## Mantenimiento

Consideraciones para el mantenimiento de la base de datos:

1. **Respaldo**: Programar respaldos diferenciales diarios y completos semanales.
2. **Purga de datos**: Implementar políticas de retención para:
   - Intentos de inicio de sesión (>90 días)
   - Registros de auditoría (>1 año)
   - Sesiones expiradas (>30 días)
   - Contraseñas antiguas (>1 año o >10 versiones)
3. **Monitoreo**: Configurar alertas para:
   - Intentos de inicio de sesión fallidos excesivos
   - Creación de usuarios administradores
   - Cambios en permisos críticos
   - Bloqueo de cuentas
4. **Índices**: Reindexar periódicamente, especialmente tablas de auditoría.
5. **Estadísticas**: Actualizar estadísticas semanalmente para optimizar el plan de consultas.

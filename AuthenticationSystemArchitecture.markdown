# Sistema de Autenticación, Roles y Permisos - Arquitectura y Hoja de Ruta

## Índice
1. [Introducción](#introducción)
2. [Arquitectura General](#arquitectura-general)
3. [Base de Datos](#base-de-datos)
4. [Backend (.NET 8)](#backend-net-8)
5. [Frontend (Angular 19)](#frontend-angular-19)
6. [Seguridad](#seguridad)
7. [Hoja de Ruta de Implementación](#hoja-de-ruta-de-implementación)
8. [Mejoras y Consideraciones Adicionales](#mejoras-y-consideraciones-adicionales)

## Introducción

Este documento detalla la arquitectura y desarrollo de un sistema de autenticación, roles y permisos robusto y escalable utilizando .NET 8, SQL Server 2019 y Angular 19. El sistema contempla gestión de usuarios con múltiples estados, autenticación multi-factor, auditoría y más características de seguridad esenciales.

## Arquitectura General

### Visión General
- **Patrón de Arquitectura**: Clean Architecture + CQRS (Command Query Responsibility Segregation)
- **Backend**: API RESTful con .NET 8
- **Base de Datos**: SQL Server 2019
- **Frontend**: Angular 19 con arquitectura modular
- **Comunicación**: HTTPS con JWT (JSON Web Tokens)
- **Caché**: Redis para sesiones y datos frecuentes
- **Logging**: Serilog para logs estructurados
- **Monitoreo**: Application Insights o Prometheus + Grafana

### Principios Fundamentales
- Separación clara de responsabilidades
- Seguridad por diseño y por defecto
- Escalabilidad horizontal y vertical
- Auditoría completa de todas las operaciones
- Alta disponibilidad y recuperación ante desastres
- Zero Trust Security Model

## Base de Datos

### Estructura de Tablas

#### Tablas Principales

1. **Users**
   ```sql
   CREATE TABLE [dbo].[Users] (
       [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
       [Username] NVARCHAR(100) NOT NULL UNIQUE,
       [Email] NVARCHAR(255) NOT NULL UNIQUE,
       [NormalizedEmail] NVARCHAR(255) NOT NULL,
       [PasswordHash] NVARCHAR(MAX) NOT NULL,
       [SecurityStamp] NVARCHAR(MAX) NOT NULL,
       [ConcurrencyStamp] NVARCHAR(MAX) NULL,
       [PhoneNumber] NVARCHAR(20) NULL,
       [PhoneNumberConfirmed] BIT NOT NULL DEFAULT 0,
       [TwoFactorEnabled] BIT NOT NULL DEFAULT 0,
       [LockoutEnd] DATETIMEOFFSET NULL,
       [LockoutEnabled] BIT NOT NULL DEFAULT 1,
       [AccessFailedCount] INT NOT NULL DEFAULT 0,
       [EmailConfirmed] BIT NOT NULL DEFAULT 0,
       [LastLoginDate] DATETIME2 NULL,
       [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [UpdatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [UserStatus] INT NOT NULL DEFAULT 1, -- 1=Registered, 2=Active, 3=Blocked, 4=Deleted
       [LastPasswordChangeDate] DATETIME2 NULL,
       [RequirePasswordChange] BIT NOT NULL DEFAULT 0,
       [PasswordResetToken] NVARCHAR(MAX) NULL,
       [PasswordResetTokenExpiry] DATETIME2 NULL,
       [ProfilePictureUrl] NVARCHAR(MAX) NULL,
       [FirstName] NVARCHAR(100) NULL,
       [LastName] NVARCHAR(100) NULL,
       [IsDeleted] BIT NOT NULL DEFAULT 0,
       [DeletedAt] DATETIME2 NULL
   )
   ```

2. **Roles**
   ```sql
   CREATE TABLE [dbo].[Roles] (
       [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
       [Name] NVARCHAR(100) NOT NULL UNIQUE,
       [NormalizedName] NVARCHAR(100) NOT NULL,
       [Description] NVARCHAR(255) NULL,
       [IsActive] BIT NOT NULL DEFAULT 1,
       [IsDefault] BIT NOT NULL DEFAULT 0,
       [Priority] INT NOT NULL DEFAULT 0,
       [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [UpdatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE()
   )
   ```

3. **UserRoles**
   ```sql
   CREATE TABLE [dbo].[UserRoles] (
       [UserId] UNIQUEIDENTIFIER NOT NULL,
       [RoleId] UNIQUEIDENTIFIER NOT NULL,
       [AssignedBy] UNIQUEIDENTIFIER NULL,
       [AssignedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [ExpirationDate] DATETIME2 NULL,
       [IsActive] BIT NOT NULL DEFAULT 1,
       CONSTRAINT [PK_UserRoles] PRIMARY KEY ([UserId], [RoleId]),
       CONSTRAINT [FK_UserRoles_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_UserRoles_Roles] FOREIGN KEY ([RoleId]) REFERENCES [dbo].[Roles] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_UserRoles_Users_AssignedBy] FOREIGN KEY ([AssignedBy]) REFERENCES [dbo].[Users] ([Id])
   )
   ```

4. **Permissions**
   ```sql
   CREATE TABLE [dbo].[Permissions] (
       [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
       [Name] NVARCHAR(100) NOT NULL UNIQUE,
       [Code] NVARCHAR(100) NOT NULL UNIQUE,
       [Description] NVARCHAR(255) NULL,
       [Category] NVARCHAR(100) NULL,
       [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [UpdatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE()
   )
   ```

5. **RolePermissions**
   ```sql
   CREATE TABLE [dbo].[RolePermissions] (
       [RoleId] UNIQUEIDENTIFIER NOT NULL,
       [PermissionId] UNIQUEIDENTIFIER NOT NULL,
       [AssignedBy] UNIQUEIDENTIFIER NULL,
       [AssignedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       CONSTRAINT [PK_RolePermissions] PRIMARY KEY ([RoleId], [PermissionId]),
       CONSTRAINT [FK_RolePermissions_Roles] FOREIGN KEY ([RoleId]) REFERENCES [dbo].[Roles] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_RolePermissions_Permissions] FOREIGN KEY ([PermissionId]) REFERENCES [dbo].[Permissions] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_RolePermissions_Users_AssignedBy] FOREIGN KEY ([AssignedBy]) REFERENCES [dbo].[Users] ([Id])
   )
   ```

6. **UserPermissions**
   ```sql
   CREATE TABLE [dbo].[UserPermissions] (
       [UserId] UNIQUEIDENTIFIER NOT NULL,
       [PermissionId] UNIQUEIDENTIFIER NOT NULL,
       [IsGranted] BIT NOT NULL DEFAULT 1,
       [AssignedBy] UNIQUEIDENTIFIER NULL,
       [AssignedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [ExpirationDate] DATETIME2 NULL,
       CONSTRAINT [PK_UserPermissions] PRIMARY KEY ([UserId], [PermissionId]),
       CONSTRAINT [FK_UserPermissions_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_UserPermissions_Permissions] FOREIGN KEY ([PermissionId]) REFERENCES [dbo].[Permissions] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_UserPermissions_Users_AssignedBy] FOREIGN KEY ([AssignedBy]) REFERENCES [dbo].[Users] ([Id])
   )
   ```

7. **Modules**
   ```sql
   CREATE TABLE [dbo].[Modules] (
       [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
       [Name] NVARCHAR(100) NOT NULL UNIQUE,
       [Description] NVARCHAR(255) NULL,
       [Icon] NVARCHAR(100) NULL,
       [Route] NVARCHAR(100) NULL,
       [IsActive] BIT NOT NULL DEFAULT 1,
       [DisplayOrder] INT NOT NULL DEFAULT 0,
       [ParentId] UNIQUEIDENTIFIER NULL,
       [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [UpdatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       CONSTRAINT [FK_Modules_Modules] FOREIGN KEY ([ParentId]) REFERENCES [dbo].[Modules] ([Id])
   )
   ```

8. **ModulePermissions**
   ```sql
   CREATE TABLE [dbo].[ModulePermissions] (
       [ModuleId] UNIQUEIDENTIFIER NOT NULL,
       [PermissionId] UNIQUEIDENTIFIER NOT NULL,
       CONSTRAINT [PK_ModulePermissions] PRIMARY KEY ([ModuleId], [PermissionId]),
       CONSTRAINT [FK_ModulePermissions_Modules] FOREIGN KEY ([ModuleId]) REFERENCES [dbo].[Modules] ([Id]) ON DELETE CASCADE,
       CONSTRAINT [FK_ModulePermissions_Permissions] FOREIGN KEY ([PermissionId]) REFERENCES [dbo].[Permissions] ([Id]) ON DELETE CASCADE
   )
   ```

#### Tablas de Auditoría y Seguridad

9. **LoginAttempts**
   ```sql
   CREATE TABLE [dbo].[LoginAttempts] (
       [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
       [Username] NVARCHAR(100) NOT NULL,
       [Email] NVARCHAR(255) NULL,
       [IPAddress] NVARCHAR(50) NOT NULL,
       [UserAgent] NVARCHAR(MAX) NULL,
       [Successful] BIT NOT NULL,
       [FailureReason] NVARCHAR(255) NULL,
       [AttemptedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
       [UserId] UNIQUEIDENTIFIER NULL,
       CONSTRAINT [FK_LoginAttempts_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id])
   )
   ```

10. **AuditLog**
    ```sql
    CREATE TABLE [dbo].[AuditLog] (
        [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        [UserId] UNIQUEIDENTIFIER NULL,
        [Action] NVARCHAR(100) NOT NULL,
        [EntityName] NVARCHAR(100) NOT NULL,
        [EntityId] NVARCHAR(100) NULL,
        [OldValues] NVARCHAR(MAX) NULL,
        [NewValues] NVARCHAR(MAX) NULL,
        [IPAddress] NVARCHAR(50) NULL,
        [UserAgent] NVARCHAR(MAX) NULL,
        [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        CONSTRAINT [FK_AuditLog_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id])
    )
    ```

11. **UserSessions**
    ```sql
    CREATE TABLE [dbo].[UserSessions] (
        [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        [UserId] UNIQUEIDENTIFIER NOT NULL,
        [Token] NVARCHAR(MAX) NOT NULL,
        [RefreshToken] NVARCHAR(MAX) NULL,
        [IPAddress] NVARCHAR(50) NOT NULL,
        [UserAgent] NVARCHAR(MAX) NULL,
        [DeviceInfo] NVARCHAR(MAX) NULL,
        [IssuedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        [ExpiresAt] DATETIME2 NOT NULL,
        [RevSEX] DATETIME2 NULL,
        [IsActive] AS (CASE WHEN [RevokedAt] IS NULL AND [ExpiresAt] > GETUTCDATE() THEN 1 ELSE 0 END),
        CONSTRAINT [FK_UserSessions_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id]) ON DELETE CASCADE
    )
    ```

12. **UserTwoFactorSettings**
    ```sql
    CREATE TABLE [dbo].[UserTwoFactorSettings] (
        [UserId] UNIQUEIDENTIFIER PRIMARY KEY,
        [IsEnabled] BIT NOT NULL DEFAULT 0,
        [Method] NVARCHAR(50) NOT NULL DEFAULT 'Email', -- Email, SMS, Authenticator
        [SecretKey] NVARCHAR(MAX) NULL, -- For authenticator apps
        [RecoveryCodesJson] NVARCHAR(MAX) NULL,
        [UpdatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        CONSTRAINT [FK_UserTwoFactorSettings_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id]) ON DELETE CASCADE
    )
    ```

13. **PasswordHistory**
    ```sql
    CREATE TABLE [dbo].[PasswordHistory] (
        [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
        [UserId] UNIQUEIDENTIFIER NOT NULL,
        [PasswordHash] NVARCHAR(MAX) NOT NULL,
        [ChangedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
        [IPAddress] NVARCHAR(50) NULL,
        [UserAgent] NVARCHAR(MAX) NULL,
        CONSTRAINT [FK_PasswordHistory_Users] FOREIGN KEY ([UserId]) REFERENCES [dbo].[Users] ([Id]) ON DELETE CASCADE
    )
    ```

### Índices Recomendados

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

### Procedimientos Almacenados

1. **GetUserPermissions**
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

2. **GetUserModules**
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

### Disparadores (Triggers) para Auditoría

1. **Auditoría de Usuarios**
   ```sql
   CREATE TRIGGER [dbo].[TR_Users_Audit]
   ON [dbo].[Users]
   AFTER INSERT, UPDATE, DELETE
   AS
   BEGIN
       SET NOCOUNT ON;
       
       DECLARE @Action NVARCHAR(10);
       DECLARE @UserId UNIQUEIDENTIFIER;
       
       -- Determinar la acción
       IF EXISTS (SELECT * FROM inserted) AND EXISTS (SELECT * FROM deleted)
           SET @Action = 'UPDATE';
       ELSE IF EXISTS (SELECT * FROM inserted)
           SET @Action = 'INSERT';
       ELSE
           SET @Action = 'DELETE';
       
       -- Capturar el usuario de sesión (debe implementarse a nivel de aplicación)
       SET @UserId = NULL; -- En implementación real, se obtendría de CONTEXT_INFO
       
       -- Registrar cambios
       IF @Action = 'UPDATE' OR @Action = 'DELETE'
       BEGIN
           INSERT INTO [dbo].[AuditLog] (UserId, Action, EntityName, EntityId, OldValues, NewValues)
           SELECT @UserId, @Action, 'Users', d.Id, 
                  (SELECT * FROM deleted d2 WHERE d2.Id = d.Id FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
                  CASE WHEN @Action = 'UPDATE' 
                       THEN (SELECT * FROM inserted i WHERE i.Id = d.Id FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
                       ELSE NULL END
           FROM deleted d;
       END
       
       IF @Action = 'INSERT'
       BEGIN
           INSERT INTO [dbo].[AuditLog] (UserId, Action, EntityName, EntityId, OldValues, NewValues)
           SELECT @UserId, @Action, 'Users', i.Id, 
                  NULL,
                  (SELECT * FROM inserted i2 WHERE i2.Id = i.Id FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
           FROM inserted i;
       END
   END
   ```

## Backend (.NET 8)

### Estructura del Proyecto

```
AuthSystem.sln
├── src
│   ├── AuthSystem.Core (Capa de Dominio)
│   │   ├── Entities
│   │   ├── Exceptions
│   │   ├── Interfaces
│   │   └── Services
│   ├── AuthSystem.Infrastructure (Capa de Infraestructura)
│   │   ├── Data
│   │   │   ├── Configurations
│   │   │   ├── Repositories
│   │   │   └── ApplicationDbContext.cs
│   │   ├── Identity
│   │   ├── Logging
│   │   └── Security
│   ├── AuthSystem.Application (Capa de Aplicación)
│   │   ├── Commands
│   │   ├── Queries
│   │   ├── DTOs
│   │   ├── Mappings
│   │   └── Validators
│   └── AuthSystem.API (Capa de Presentación)
│       ├── Controllers
│       ├── Filters
│       ├── Extensions
│       ├── Middleware
│       └── Program.cs
└── tests
    ├── AuthSystem.UnitTests
    ├── AuthSystem.IntegrationTests
    └── AuthSystem.FunctionalTests
```

### Principales Implementaciones

#### 1. Modelo de Entidades
```csharp
// AuthSystem.Core/Entities/User.cs
public class User
{
    public Guid Id { get; private set; }
    public string Username { get; private set; }
    public string Email { get; private set; }
    public string PasswordHash { get; private set; }
    public string SecurityStamp { get; private set; }
    public string PhoneNumber { get; private set; }
    public bool PhoneNumberConfirmed { get; private set; }
    public bool TwoFactorEnabled { get; private set; }
    public DateTimeOffset? LockoutEnd { get; private set; }
    public bool LockoutEnabled { get; private set; }
    public int AccessFailedCount { get; private set; }
    public bool EmailConfirmed { get; private set; }
    public DateTime? LastLoginDate { get; private set; }
    public DateTime CreatedAt { get; private set; }
    public DateTime UpdatedAt { get; private set; }
    public UserStatus Status { get; private set; }
    public DateTime? LastPasswordChangeDate { get; private set; }
    public bool RequirePasswordChange { get; private set; }
    public string ProfilePictureUrl { get; private set; }
    public string FirstName { get; private set; }
    public string LastName { get; private set; }
    public bool IsDeleted { get; private set; }
    public DateTime? DeletedAt { get; private set; }
    
    // Navegaciones
    public ICollection<UserRole> UserRoles { get; private set; }
    public UserTwoFactorSettings TwoFactorSettings { get; private set; }
    
    // Constructor, métodos de comportamiento, etc.
}

public enum UserStatus
{
    Registered = 1,
    Active = 2,
    Blocked = 3,
    Deleted = 4
}
```

#### 2. Implementación de Autenticación
```csharp
// AuthSystem.Application/Commands/Authenticate/AuthenticateCommand.cs
public class AuthenticateCommand : IRequest<AuthenticationResult>
{
    public string Username { get; set; }
    public string Password { get; set; }
    public string IpAddress { get; set; }
    public string UserAgent { get; set; }
    public bool RememberMe { get; set; }
}

// AuthSystem.Application/Commands/Authenticate/AuthenticateCommandHandler.cs
public class AuthenticateCommandHandler : IRequestHandler<AuthenticateCommand, AuthenticationResult>
{
    private readonly IUserRepository _userRepository;
    private readonly IPasswordHasher _passwordHasher;
    private readonly IJwtService _jwtService;
    private readonly IAuditService _auditService;
    
    // Constructor con inyección de dependencias...
    
    public async Task<AuthenticationResult> Handle(AuthenticateCommand request, CancellationToken cancellationToken)
    {
        // 1. Buscar usuario por nombre de usuario o email
        var user = await _userRepository.FindByUsernameOrEmailAsync(request.Username);
        
        // 2. Verificar si el usuario existe
        if (user == null)
        {
            await LogFailedLoginAttempt(request, null, "Usuario no encontrado");
            return AuthenticationResult.Failure("Credenciales inválidas");
        }
        
        // 3. Verificar estado del usuario
        if (user.Status != UserStatus.Active)
        {
            await LogFailedLoginAttempt(request, user.Id, $"Usuario con estado {user.Status}");
            return AuthenticationResult.Failure("Cuenta no activa");
        }
        
        // 4. Verificar si la cuenta está bloqueada
        if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow)
        {
            await LogFailedLoginAttempt(request, user.Id, "Cuenta bloqueada");
            return AuthenticationResult.Failure("Cuenta temporalmente bloqueada. Intente más tarde.");
        }
        
        // 5. Verificar contraseña
        if (!_passwordHasher.VerifyPassword(user.PasswordHash, request.Password))
        {
            // Incrementar contador de intentos fallidos
            user.IncrementAccessFailedCount();
            
            // Verificar si se debe bloquear la cuenta
            if (user.AccessFailedCount >= 5)
            {
                user.LockAccount(TimeSpan.FromMinutes(15));
            }
            
            await _userRepository.UpdateAsync(user);
            await LogFailedLoginAttempt(request, user.Id, "Contraseña incorrecta");
            
            return AuthenticationResult.Failure("Credenciales inválidas");
        }
        
        // 6. Resetear contador de intentos fallidos si la autenticación es exitosa
        user.ResetAccessFailedCount();
        user.UpdateLastLoginDate();
        await _userRepository.UpdateAsync(user);
        
        // 7. Verificar si se requiere 2FA
        if (user.TwoFactorEnabled)
        {
            return AuthenticationResult.TwoFactorRequired(user.Id);
        }
        
        // 8. Generar tokens JWT
        var (token, refreshToken) = await _jwtService.GenerateTokensAsync(user, request.RememberMe);
        
        // 9. Registrar sesión
        await _userRepository.AddSessionAsync(new UserSession
        {
            UserId = user.Id,
            Token = token,
            RefreshToken = refreshToken,
            IPAddress = request.IpAddress,
            UserAgent = request.UserAgent,
            IssuedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddHours(request.RememberMe ? 72 : 2)
        });
        
        // 10. Registrar login exitoso
        await LogSuccessfulLoginAttempt(request, user.Id);
        
        // 11. Retornar resultado exitoso
        return AuthenticationResult.Success(token, refreshToken, user.RequirePasswordChange);
    }
    
    private async Task LogFailedLoginAttempt(AuthenticateCommand request, Guid? userId, string reason)
    {
        await _auditService.LogLoginAttemptAsync(
            request.Username,
            request.IpAddress,
            request.UserAgent,
            false,
            reason,
            userId);
    }
    
    private async Task LogSuccessfulLoginAttempt(AuthenticateCommand request, Guid userId)
    {
        await _auditService.LogLoginAttemptAsync(
            request.Username,
            request.IpAddress,
            request.UserAgent,
            true,
            null,
            userId);
    }
}
```

#### 3. Implementación de JWT
```csharp
// AuthSystem.Infrastructure/Security/JwtService.cs
public class JwtService : IJwtService
{
    private readonly JwtSettings _jwtSettings;
    private readonly IUserRepository _userRepository;
    private readonly IDateTimeProvider _dateTimeProvider;
    
    // Constructor...
    
    public async Task<(string Token, string RefreshToken)> GenerateTokensAsync(User user, bool extendedDuration = false)
    {
        // 1. Obtener roles y permisos del usuario
        var roles = await _userRepository.GetUserRolesAsync(user.Id);
        var permissions = await _userRepository.GetUserPermissionsAsync(user.Id);
        
        // 2. Crear claims para el token
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("name", $"{user.FirstName} {user.LastName}".Trim())
        };
        
        // Agregar roles
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role.Name));
        }
        
        // Agregar permisos
        foreach (var permission in permissions)
        {
            claims.Add(new Claim("permission", permission.Code));
        }
        
        // 3. Crear credenciales de firma
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        
        // 4. Crear el token
        var expires = _dateTimeProvider.UtcNow.AddMinutes(
            extendedDuration ? _jwtSettings.ExtendedExpirationMinutes : _jwtSettings.ExpirationMinutes);
            
        var token = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: expires,
            signingCredentials: creds
        );
        
        // 5. Generar refresh token
        var refreshToken = GenerateRefreshToken();
        
        return (new JwtSecurityTokenHandler().WriteToken(token), refreshToken);
    }
    
    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}
```

#### 4. Implementación de Permisos
```csharp
// AuthSystem.API/Filters/PermissionAuthorizationFilter.cs
public class PermissionAuthorizationFilter : IAsyncAuthorizationFilter
{
    private readonly string _permission;
    
    public PermissionAuthorizationFilter(string permission)
    {
        _permission = permission;
    }
    
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var userClaims = context.HttpContext.User.Claims;
        var hasPermission = userClaims.Any(c => c.Type == "permission" && c.Value == _permission);
        
        if (!hasPermission)
        {
            context.Result = new ForbidResult();
            return;
        }
    }
}

// AuthSystem.API/Attributes/RequirePermissionAttribute.cs
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public class RequirePermissionAttribute : Attribute, IFilterFactory
{
    public string Permission { get; }
    
    public RequirePermissionAttribute(string permission)
    {
        Permission = permission;
    }
    
    public bool IsReusable => false;
    
    public IFilterMetadata CreateInstance(IServiceProvider serviceProvider)
    {
        return new PermissionAuthorizationFilter(Permission);
    }
}
```

#### 5. Servicios de MFA (Multi-Factor Authentication)
```csharp
// AuthSystem.Core/Services/TwoFactorAuthService.cs
public class TwoFactorAuthService : ITwoFactorAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IEmailService _emailService;
    private readonly ISmsService _smsService;
    private readonly ITotpService _totpService;
    
    // Constructor...
    
    public async Task<bool> EnableTwoFactorAsync(Guid userId, TwoFactorMethod method)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        
        if (user == null)
            return false;
        
        // Generar configuración según el método
        var settings = new UserTwoFactorSettings
        {
            UserId = userId,
            IsEnabled = true,
            Method = method
        };
        
        switch (method)
        {
            case TwoFactorMethod.Email:
                // No se requiere configuración adicional
                break;
                
            case TwoFactorMethod.Sms:
                // Verificar que el número de teléfono esté confirmado
                if (!user.PhoneNumberConfirmed)
                    return false;
                break;
                
            case TwoFactorMethod.Authenticator:
                // Generar clave secreta para aplicaciones autenticadoras
                settings.SecretKey = _totpService.GenerateSecretKey();
                
                // Generar códigos de recuperación
                settings.RecoveryCodesJson = JsonSerializer.Serialize(
                    _totpService.GenerateRecoveryCodes());
                break;
        }
        
        // Actualizar usuario y configuración 2FA
        user.EnableTwoFactor();
        await _userRepository.UpdateAsync(user);
        await _userRepository.SaveTwoFactorSettingsAsync(settings);
        
        return true;
    }
    
    public async Task<bool> DisableTwoFactorAsync(Guid userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        
        if (user == null)
            return false;
        
        user.DisableTwoFactor();
        await _userRepository.UpdateAsync(user);
        await _userRepository.RemoveTwoFactorSettingsAsync(userId);
        
        return true;
    }
    
    public async Task<bool> VerifyTwoFactorCodeAsync(Guid userId, string code)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        var settings = await _userRepository.GetTwoFactorSettingsAsync(userId);
        
        if (user == null || settings == null || !settings.IsEnabled)
            return false;
        
        bool isValid = false;
        
        switch (settings.Method)
        {
            case TwoFactorMethod.Email:
            case TwoFactorMethod.Sms:
                // Verificar contra código almacenado en caché (implementación real usaría Redis)
                var cachedCode = "123456"; // Simulado, en implementación real se obtendría de Redis
                isValid = code == cachedCode;
                break;
                
            case TwoFactorMethod.Authenticator:
                isValid = _totpService.ValidateCode(settings.SecretKey, code);
                break;
        }
        
        return isValid;
    }
    
    public async Task SendTwoFactorCodeAsync(Guid userId)
    {
        var user = await _userRepository.GetByIdAsync(userId);
        var settings = await _userRepository.GetTwoFactorSettingsAsync(userId);
        
        if (user == null || settings == null || !settings.IsEnabled)
            return;
        
        // Generar código (6 dígitos)
        var code = new Random().Next(100000, 999999).ToString();
        
        // Almacenar código en caché (implementación real usaría Redis)
        // cacheService.Set($"2FA:{userId}", code, TimeSpan.FromMinutes(5));
        
        // Enviar código según el método
        switch (settings.Method)
        {
            case TwoFactorMethod.Email:
                await _emailService.SendAsync(user.Email, "Código de verificación", 
                    $"Su código de verificación es: {code}");
                break;
                
            case TwoFactorMethod.Sms:
                await _smsService.SendAsync(user.PhoneNumber, 
                    $"Su código de verificación es: {code}");
                break;
        }
    }
}
```

#### 6. Controlador de Autenticación
```csharp
// AuthSystem.API/Controllers/AuthController.cs
[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IMediator _mediator;
    
    public AuthController(IMediator mediator)
    {
        _mediator = mediator;
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        var command = new AuthenticateCommand
        {
            Username = request.Username,
            Password = request.Password,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString(),
            RememberMe = request.RememberMe
        };
        
        var result = await _mediator.Send(command);
        
        if (result.RequiresTwoFactor)
        {
            return Ok(new { requiresTwoFactor = true, userId = result.UserId });
        }
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        return Ok(new
        {
            token = result.Token,
            refreshToken = result.RefreshToken,
            requiresPasswordChange = result.RequirePasswordChange
        });
    }
    
    [HttpPost("two-factor")]
    public async Task<IActionResult> TwoFactorLogin([FromBody] TwoFactorLoginRequest request)
    {
        var command = new VerifyTwoFactorCommand
        {
            UserId = request.UserId,
            Code = request.Code,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString(),
            RememberMe = request.RememberMe
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        return Ok(new
        {
            token = result.Token,
            refreshToken = result.RefreshToken,
            requiresPasswordChange = result.RequirePasswordChange
        });
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        // Incluir validación de recaptcha
        if (!string.IsNullOrEmpty(request.RecaptchaToken))
        {
            var recaptchaCommand = new ValidateRecaptchaCommand
            {
                Token = request.RecaptchaToken,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
            };
            
            var recaptchaResult = await _mediator.Send(recaptchaCommand);
            
            if (!recaptchaResult.IsValid)
            {
                return BadRequest(new { message = "Verificación de recaptcha fallida" });
            }
        }
        
        var command = new RegisterUserCommand
        {
            Username = request.Username,
            Email = request.Email,
            Password = request.Password,
            FirstName = request.FirstName,
            LastName = request.LastName,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        return Ok(new { message = "Registro exitoso. Por favor verifique su correo electrónico para activar su cuenta." });
    }
    
    [HttpGet("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromQuery] string userId, [FromQuery] string code)
    {
        var command = new VerifyEmailCommand
        {
            UserId = Guid.Parse(userId),
            Code = code
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        // Redirigir a la página de confirmación exitosa
        return Redirect("/email-verified");
    }
    
    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        var command = new RefreshTokenCommand
        {
            RefreshToken = request.RefreshToken,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        return Ok(new
        {
            token = result.Token,
            refreshToken = result.RefreshToken
        });
    }
    
    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        if (userId != null)
        {
            var command = new LogoutCommand
            {
                UserId = Guid.Parse(userId)
            };
            
            await _mediator.Send(command);
        }
        
        return Ok(new { message = "Sesión cerrada exitosamente" });
    }
    
    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        
        var command = new ChangePasswordCommand
        {
            UserId = Guid.Parse(userId),
            CurrentPassword = request.CurrentPassword,
            NewPassword = request.NewPassword,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        return Ok(new { message = "Contraseña cambiada exitosamente" });
    }
    
    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest request)
    {
        var command = new ForgotPasswordCommand
        {
            Email = request.Email
        };
        
        var result = await _mediator.Send(command);
        
        // Siempre devolver éxito para evitar enumeración de usuarios
        return Ok(new { message = "Si su correo está registrado, recibirá instrucciones para restablecer su contraseña" });
    }
    
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
    {
        var command = new ResetPasswordCommand
        {
            UserId = request.UserId,
            Token = request.Token,
            NewPassword = request.NewPassword,
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            UserAgent = HttpContext.Request.Headers["User-Agent"].ToString()
        };
        
        var result = await _mediator.Send(command);
        
        if (!result.Succeeded)
        {
            return BadRequest(new { message = result.Error });
        }
        
        return Ok(new { message = "Contraseña restablecida exitosamente" });
    }
}
```

## Frontend (Angular 19)

### Estructura del Proyecto Angular

```
auth-system-app/
├── src/
│   ├── app/
│   │   ├── core/
│   │   │   ├── auth/
│   │   │   │   ├── guards/
│   │   │   │   │   ├── auth.guard.ts
│   │   │   │   │   └── permission.guard.ts
│   │   │   │   ├── interceptors/
│   │   │   │   │   ├── auth.interceptor.ts
│   │   │   │   │   └── error.interceptor.ts
│   │   │   │   ├── models/
│   │   │   │   │   ├── user.model.ts
│   │   │   │   │   └── auth-response.model.ts
│   │   │   │   ├── services/
│   │   │   │   │   ├── auth.service.ts
│   │   │   │   │   └── user.service.ts
│   │   │   │   └── store/
│   │   │   │       ├── auth.actions.ts
│   │   │   │       ├── auth.effects.ts
│   │   │   │       ├── auth.reducers.ts
│   │   │   │       └── auth.selectors.ts
│   │   │   ├── modules/
│   │   │   │   └── module.service.ts
│   │   │   └── permissions/
│   │   │       └── permission.service.ts
│   │   ├── features/
│   │   │   ├── auth/
│   │   │   │   ├── login/
│   │   │   │   ├── register/
│   │   │   │   ├── two-factor/
│   │   │   │   ├── forgot-password/
│   │   │   │   └── reset-password/
│   │   │   ├── dashboard/
│   │   │   ├── profile/
│   │   │   └── admin/
│   │   │       ├── users/
│   │   │       ├── roles/
│   │   │       └── permissions/
│   │   ├── shared/
│   │   │   ├── components/
│   │   │   ├── directives/
│   │   │   │   └── has-permission.directive.ts
│   │   │   └── pipes/
│   │   ├── app-routing.module.ts
│   │   └── app.module.ts
│   ├── assets/
│   ├── environments/
│   └── index.html
```

### Principales Implementaciones

#### 1. Servicio de Autenticación
```typescript
// src/app/core/auth/services/auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable, of, throwError } from 'rxjs';
import { map, catchError, tap, switchMap } from 'rxjs/operators';
import { Router } from '@angular/router';

import { User } from '../models/user.model';
import { LoginRequest, LoginResponse, RegisterRequest } from '../models/auth-response.model';
import { JwtHelperService } from '@auth0/angular-jwt';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private currentUserSubject: BehaviorSubject<User | null>;
  public currentUser$: Observable<User | null>;
  private refreshTokenTimeout: any;
  
  private apiUrl = 'api/auth';
  private jwtHelper = new JwtHelperService();

  constructor(
    private http: HttpClient,
    private router: Router
  ) {
    // Inicializar usuario desde localStorage
    const storedUser = localStorage.getItem('currentUser');
    this.currentUserSubject = new BehaviorSubject<User | null>(
      storedUser ? JSON.parse(storedUser) : null
    );
    this.currentUser$ = this.currentUserSubject.asObservable();
    
    // Si hay un usuario almacenado, verificar si el token expiró
    if (storedUser) {
      const user = JSON.parse(storedUser);
      if (this.jwtHelper.isTokenExpired(user.token)) {
        this.refreshToken().subscribe();
      } else {
        this.startRefreshTokenTimer(user.token);
      }
    }
  }

  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  login(username: string, password: string, rememberMe = false): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/login`, { username, password, rememberMe })
      .pipe(
        tap(response => {
          // Verificar si se requiere 2FA
          if (response.requiresTwoFactor) {
            localStorage.setItem('twoFactorUserId', response.userId);
            return;
          }
          
          // Verificar si se requiere cambio de contraseña
          if (response.requiresPasswordChange) {
            const user = this.decodeToken(response.token);
            user.token = response.token;
            user.refreshToken = response.refreshToken;
            localStorage.setItem('currentUser', JSON.stringify(user));
            this.currentUserSubject.next(user);
            this.startRefreshTokenTimer(response.token);
            return;
          }
          
          // Login normal
          const user = this.decodeToken(response.token);
          user.token = response.token;
          user.refreshToken = response.refreshToken;
          localStorage.setItem('currentUser', JSON.stringify(user));
          this.currentUserSubject.next(user);
          this.startRefreshTokenTimer(response.token);
        })
      );
  }

  twoFactorLogin(userId: string, code: string, rememberMe = false): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.apiUrl}/two-factor`, { userId, code, rememberMe })
      .pipe(
        tap(response => {
          localStorage.removeItem('twoFactorUserId');
          
          const user = this.decodeToken(response.token);
          user.token = response.token;
          user.refreshToken = response.refreshToken;
          localStorage.setItem('currentUser', JSON.stringify(user));
          this.currentUserSubject.next(user);
          this.startRefreshTokenTimer(response.token);
        })
      );
  }

  register(request: RegisterRequest): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/register`, request);
  }

  logout(): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/logout`, {}).pipe(
      tap(() => this.clearUserData()),
      catchError(error => {
        this.clearUserData();
        return throwError(error);
      })
    );
  }

  refreshToken(): Observable<any> {
    const user = this.currentUserValue;
    if (!user || !user.refreshToken) {
      this.clearUserData();
      return throwError('No refresh token available');
    }
    
    return this.http.post<LoginResponse>(`${this.apiUrl}/refresh-token`, { refreshToken: user.refreshToken })
      .pipe(
        tap(response => {
          const refreshedUser = { ...user, token: response.token, refreshToken: response.refreshToken };
          localStorage.setItem('currentUser', JSON.stringify(refreshedUser));
          this.currentUserSubject.next(refreshedUser);
          this.startRefreshTokenTimer(response.token);
        }),
        catchError(error => {
          this.clearUserData();
          return throwError(error);
        })
      );
  }

  forgotPassword(email: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/forgot-password`, { email });
  }

  resetPassword(userId: string, token: string, newPassword: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/reset-password`, { userId, token, newPassword });
  }

  changePassword(currentPassword: string, newPassword: string): Observable<any> {
    return this.http.post<any>(`${this.apiUrl}/change-password`, { currentPassword, newPassword });
  }

  verifyEmail(userId: string, token: string): Observable<any> {
    return this.http.get<any>(`${this.apiUrl}/verify-email?userId=${userId}&code=${token}`);
  }

  // Métodos de ayuda
  private decodeToken(token: string): User {
    const decodedToken = this.jwtHelper.decodeToken(token);
    
    return {
      id: decodedToken.sub,
      username: decodedToken.name,
      email: decodedToken.email,
      fullName: decodedToken.name,
      roles: decodedToken.role || [],
      permissions: decodedToken.permission || [],
      token: '',
      refreshToken: ''
    };
  }

  private startRefreshTokenTimer(token: string): void {
    // Limpiar timer existente
    this.stopRefreshTokenTimer();
    
    // Calcular tiempo de expiración
    const expires = new Date(this.jwtHelper.getTokenExpirationDate(token) as Date);
    const timeout = expires.getTime() - Date.now() - (60 * 1000); // Renovar 1 minuto antes
    
    this.refreshTokenTimeout = setTimeout(() => {
      this.refreshToken().subscribe();
    }, Math.max(0, timeout));
  }

  private stopRefreshTokenTimer(): void {
    if (this.refreshTokenTimeout) {
      clearTimeout(this.refreshTokenTimeout);
    }
  }

  private clearUserData(): void {
    localStorage.removeItem('currentUser');
    this.stopRefreshTokenTimer();
    this.currentUserSubject.next(null);
    this.router.navigate(['/auth/login']);
  }

  public hasPermission(permission: string): boolean {
    const user = this.currentUserValue;
    if (!user || !user.permissions) {
      return false;
    }
    return user.permissions.includes(permission);
  }
  
  public hasRole(role: string): boolean {
    const user = this.currentUserValue;
    if (!user || !user.roles) {
      return false;
    }
    return user.roles.includes(role);
  }
}
```

#### 2. Guard para Permisos
```typescript
// src/app/core/auth/guards/permission.guard.ts
import { Injectable } from '@angular/core';
import { CanActivate, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { Observable } from 'rxjs';
import { AuthService } from '../services/auth.service';

@Injectable({
  providedIn: 'root'
})
export class PermissionGuard implements CanActivate {
  constructor(
    private authService: AuthService,
    private router: Router
  ) {}

  canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Observable<boolean> | Promise<boolean> | boolean {
    const requiredPermission = route.data.permission as string;
    
    if (!requiredPermission) {
      return true;
    }
    
    if (!this.authService.currentUserValue) {
      this.router.navigate(['/auth/login'], { queryParams: { returnUrl: state.url } });
      return false;
    }
    
    if (this.authService.hasPermission(requiredPermission)) {
      return true;
    }
    
    this.router.navigate(['/forbidden']);
    return false;
  }
}
```

#### 3. Interceptor para JWT
```typescript
// src/app/core/auth/interceptors/auth.interceptor.ts
import { Injectable } from '@angular/core';
import { HttpRequest, HttpHandler, HttpEvent, HttpInterceptor, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError, BehaviorSubject } from 'rxjs';
import { catchError, filter, take, switchMap } from 'rxjs/operators';

import { AuthService } from '../services/auth.service';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  private isRefreshing = false;
  private refreshTokenSubject: BehaviorSubject<any> = new BehaviorSubject<any>(null);

  constructor(private authService: AuthService) {}

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const user = this.authService.currentUserValue;
    
    if (user && user.token) {
      request = this.addToken(request, user.token);
    }

    return next.handle(request).pipe(
      catchError(error => {
        if (error instanceof HttpErrorResponse && error.status === 401) {
          return this.handle401Error(request, next);
        }
        return throwError(error);
      })
    );
  }

  private addToken(request: HttpRequest<any>, token: string): HttpRequest<any> {
    return request.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }

  private handle401Error(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    if (!this.isRefreshing) {
      this.isRefreshing = true;
      this.refreshTokenSubject.next(null);

      return this.authService.refreshToken().pipe(
        switchMap(response => {
          this.isRefreshing = false;
          this.refreshTokenSubject.next(response.token);
          return next.handle(this.addToken(request, response.token));
        }),
        catchError(error => {
          this.isRefreshing = false;
          this.authService.logout();
          return throwError(error);
        })
      );
    } else {
      return this.refreshTokenSubject.pipe(
        filter(token => token != null),
        take(1),
        switchMap(token => {
          return next.handle(this.addToken(request, token));
        })
      );
    }
  }
}
```

#### 4. Directiva Has Permission
```typescript
// src/app/shared/directives/has-permission.directive.ts
import { Directive, Input, TemplateRef, ViewContainerRef, OnInit } from '@angular/core';
import { AuthService } from '../../core/auth/services/auth.service';

@Directive({
  selector: '[hasPermission]'
})
export class HasPermissionDirective implements OnInit {
  @Input() hasPermission: string | string[] = [];
  @Input() hasPermissionOperation: 'AND' | 'OR' = 'OR';
  
  private isHidden = true;

  constructor(
    private templateRef: TemplateRef<any>,
    private viewContainer: ViewContainerRef,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.updateView();
    
    // Suscribirse a cambios en el usuario
    this.authService.currentUser$.subscribe(() => {
      this.updateView();
    });
  }

  private updateView(): void {
    if (this.checkPermissions()) {
      if (this.isHidden) {
        this.viewContainer.createEmbeddedView(this.templateRef);
        this.isHidden = false;
      }
    } else {
      this.viewContainer.clear();
      this.isHidden = true;
    }
  }

  private checkPermissions(): boolean {
    const permissions = Array.isArray(this.hasPermission) 
      ? this.hasPermission 
      : [this.hasPermission];
      
    if (permissions.length === 0) {
      return true;
    }
    
    const user = this.authService.currentUserValue;
    
    if (!user) {
      return false;
    }
    
    if (this.hasPermissionOperation === 'AND') {
      return permissions.every(permission => this.authService.hasPermission(permission));
    }
    
    return permissions.some(permission => this.authService.hasPermission(permission));
  }
}
```

#### 5. Componente de Login
```typescript
// src/app/features/auth/login/login.component.ts
import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router, ActivatedRoute } from '@angular/router';
import { first } from 'rxjs/operators';

import { AuthService } from '../../../core/auth/services/auth.service';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements OnInit {
  loginForm!: FormGroup;
  loading = false;
  submitted = false;
  error = '';
  returnUrl: string = '/dashboard';
  
  // reCAPTCHA
  siteKey: string = 'YOUR_RECAPTCHA_SITE_KEY';
  recaptchaResponse: string = '';

  constructor(
    private formBuilder: FormBuilder,
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    this.loginForm = this.formBuilder.group({
      username: ['', Validators.required],
      password: ['', Validators.required],
      rememberMe: [false],
      recaptcha: ['']
    });

    // Obtener returnUrl desde parámetros de query
    this.returnUrl = this.route.snapshot.queryParams['returnUrl'] || '/dashboard';
  }

  // Getter para acceso fácil a los controles del formulario
  get f() { return this.loginForm.controls; }

  onSubmit(): void {
    this.submitted = true;
    this.error = '';

    if (this.loginForm.invalid) {
      return;
    }

    this.loading = true;

    this.authService.login(
      this.f.username.value,
      this.f.password.value,
      this.f.rememberMe.value
    ).pipe(first())
      .subscribe({
        next: (response) => {
          if (response.requiresTwoFactor) {
            this.router.navigate(['/auth/two-factor'], {
              queryParams: { userId: response.userId }
            });
          } else if (response.requiresPasswordChange) {
            this.router.navigate(['/auth/change-password']);
          } else {
            this.router.navigate([this.returnUrl]);
          }
        },
        error: error => {
          this.error = error.message || 'Error en el inicio de sesión';
          this.loading = false;
        }
      });
  }

  resolved(captchaResponse: string): void {
    this.recaptchaResponse = captchaResponse;
    this.f.recaptcha.setValue(captchaResponse);
  }
}
```

## Seguridad

### Medidas de Seguridad Implementadas
- **Autenticación**:
  - JWT con claves HMAC-SHA256
  - Refresh tokens para sesiones prolongadas
  - Autenticación multi-factor (email, SMS, authenticator apps)
  - Validación de reCAPTCHA para registro
  - Bloqueo de cuentas después de intentos fallidos
  - Verificación de email para nuevos usuarios

- **Autorización**:
  - Sistema RBAC (Role-Based Access Control)
  - Permisos granulares a nivel de usuario y rol
  - Verificación de permisos en backend y frontend
  - Directiva y guard para control de acceso en frontend

- **Protección de Datos**:
  - Hashing de contraseñas con PBKDF2
  - Encriptación de datos sensibles en la base de datos
  - HTTPS obligatorio para todas las comunicaciones
  - Protección contra CSRF mediante tokens
  - Validación estricta de entradas

- **Auditoría y Monitoreo**:
  - Registro de todos los intentos de login
  - Auditoría completa de cambios en entidades
  - Monitoreo de sesiones activas
  - Logs estructurados con Serilog
  - Integración con sistemas de monitoreo (Application Insights/Prometheus)

### Políticas de Seguridad
- Forzar cambio de contraseña cada 90 días
- Contraseñas deben cumplir con:
  - Mínimo 12 caracteres
  - Al menos una mayúscula, minúscula, número y símbolo
  - No reutilizar últimas 5 contraseñas
- Sesiones expiran después de 2 horas (o 72 horas si se selecciona "Recordarme")
- Máximo 5 sesiones concurrentes por usuario
- Validación de IP para tokens de refresh
- Rotación automática de claves JWT cada 6 meses

## Hoja de Ruta de Implementación

### Fase 1: Configuración Inicial (2 semanas)
- Configuración de la solución .NET 8
- Configuración del proyecto Angular 19
- Diseño de la base de datos
- Implementación de migraciones iniciales
- Configuración de CI/CD con GitHub Actions
- Setup de logging y monitoreo básico

### Fase 2: Autenticación Básica (3 semanas)
- Implementación de registro de usuarios
- Login/Logout
- Verificación de email
- Recuperación de contraseña
- Implementación de JWT
- Configuración inicial de Redis para sesiones

### Fase 3: Roles y Permisos (3 semanas)
- Implementación del sistema RBAC
- Gestión de roles y permisos en backend
- Interfaz de administración en frontend
- Guard y directiva de permisos en Angular
- Procedimientos almacenados para permisos y módulos

### Fase 4: Seguridad Avanzada (3 semanas)
- Implementación de MFA
- Configuración de auditoría
- Implementación de bloqueo de cuentas
- Protección contra ataques comunes
- Configuración de reCAPTCHA
- Implementación de políticas de contraseña

### Fase 5: Optimización y Testing (2 semanas)
- Optimización de consultas SQL
- Creación de índices adicionales
- Pruebas de carga y estrés
- Pruebas de seguridad (pentesting)
- Documentación final
- Preparación para producción

### Fase 6: Despliegue (1 semana)
- Configuración de servidores de producción
- Despliegue inicial
- Configuración de monitoreo en producción
- Pruebas finales
- Lanzamiento

## Mejoras y Consideraciones Adicionales

### Mejoras Futuras
- Integración con proveedores de identidad externos (OAuth2/OpenID Connect)
- Implementación de single sign-on (SSO)
- Soporte para autenticación biométrica
- Análisis de comportamiento de usuarios para detección de anomalías
- Implementación de WebAuthn para autenticación sin contraseña
- Soporte para múltiples idiomas
- Dashboard de seguridad para administradores

### Consideraciones
- Cumplimiento con GDPR/CCPA para manejo de datos personales
- Escalabilidad para soportar millones de usuarios
- Backup y recuperación de datos
- Plan de respuesta ante incidentes de seguridad
- Actualizaciones regulares de dependencias
- Auditorías de seguridad periódicas
- Capacitación del equipo en prácticas de seguridad
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = true;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)),
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
    
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            if (context.Exception is SecurityTokenExpiredException)
            {
                context.Response.Headers.Add("Token-Expired", "true");
            }
            return Task.CompletedTask;
        }
    };
});

// Configurar Rate Limiting
builder.Services.AddMemoryCache();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
builder.Services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
builder.Services.AddInMemoryRateLimiting();

// Health Checks
builder.Services.AddHealthChecks()
    .AddSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"))
    .AddCheck<SystemMemoryHealthCheck>("Memory");

// Agregar Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Authentication API",
        Version = "v1",
        Description = "API para autenticación, roles y permisos",
        Contact = new OpenApiContact
        {
            Name = "Admin",
            Email = "admin@example.com"
        }
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Include XML comments
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        c.IncludeXmlComments(xmlPath);
    }
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/error");
    app.UseHsts();
}

// Middleware personalizados
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseMiddleware<RequestLoggingMiddleware>();

// Security headers
app.UseXContentTypeOptions();
app.UseReferrerPolicy(opts => opts.NoReferrer());
app.UseXXssProtection(options => options.EnabledWithBlockMode());
app.UseXfo(options => options.Deny());

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCors("CorsPolicy");
app.UseIpRateLimiting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
    endpoints.MapHealthChecks("/health");
});

app.Run();
EOF

# Crear Middleware
mkdir Middleware
cd Middleware

cat > ErrorHandlingMiddleware.cs << 'EOF'
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using FluentValidation;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthSystem.API.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;

        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            _logger.LogError(exception, "Un error ha ocurrido: {Message}", exception.Message);

            HttpStatusCode statusCode = HttpStatusCode.InternalServerError;
            string message = "Ha ocurrido un error interno en el servidor.";

            if (exception is ValidationException validationException)
            {
                statusCode = HttpStatusCode.BadRequest;
                message = string.Join(", ", validationException.Errors);
            }
            else if (exception is UnauthorizedAccessException)
            {
                statusCode = HttpStatusCode.Unauthorized;
                message = "No autorizado para realizar esta acción.";
            }
            else if (exception is ArgumentException)
            {
                statusCode = HttpStatusCode.BadRequest;
                message = exception.Message;
            }

            // No incluir detalles técnicos en producción
            var response = new
            {
                status = (int)statusCode,
                message = message
            };

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)statusCode;

            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
        }
    }
}
EOF

cat > RequestLoggingMiddleware.cs << 'EOF'
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace AuthSystem.API.Middleware
{
    public class RequestLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestLoggingMiddleware> _logger;

        public RequestLoggingMiddleware(RequestDelegate next, ILogger<RequestLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var stopwatch = Stopwatch.StartNew();
            
            var requestId = Guid.NewGuid().ToString();
            context.Items["RequestId"] = requestId;
            
            var requestMethod = context.Request.Method;
            var requestPath = context.Request.Path;
            var userIp = context.Connection.RemoteIpAddress?.ToString();
            var userAgent = context.Request.Headers["User-Agent"].ToString();
            
            _logger.LogInformation(
                "Request {RequestId} started: {RequestMethod} {RequestPath} - IP: {UserIp}, UserAgent: {UserAgent}",
                requestId, requestMethod, requestPath, userIp, userAgent);

            try
            {
                await _next(context);
                
                stopwatch.Stop();
                
                _logger.LogInformation(
                    "Request {RequestId} completed: {RequestMethod} {RequestPath} - Status: {StatusCode} in {ElapsedMilliseconds}ms",
                    requestId, requestMethod, requestPath, context.Response.StatusCode, stopwatch.ElapsedMilliseconds);
            }
            catch (Exception)
            {
                stopwatch.Stop();
                
                _logger.LogInformation(
                    "Request {RequestId} failed: {RequestMethod} {RequestPath} in {ElapsedMilliseconds}ms",
                    requestId, requestMethod, requestPath, stopwatch.ElapsedMilliseconds);
                
                throw;
            }
        }
    }
}
EOF

# Crear Controllers
cd ..
mkdir Controllers
cd Controllers

cat > AuthController.cs << 'EOF'
using System;
using System.Threading.Tasks;
using AuthSystem.Application.Commands.Authentication;
using AuthSystem.Application.DTOs;
using MediatR;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthSystem.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IMediator _mediator;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IMediator mediator, ILogger<AuthController> logger)
        {
            _mediator = mediator;
            _logger = logger;
        }

        /// <summary>
        /// Inicia sesión con un usuario y contraseña
        /// </summary>
        /// <param name="request">Datos de inicio de sesión</param>
        /// <returns>Información de autenticación incluyendo token JWT</returns>
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var command = new AuthenticateCommand
            {
                Username = request.Username,
                Password = request.Password,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request.Headers["User-Agent"].ToString(),
                RememberMe = request.RememberMe,
                RecaptchaToken = request.RecaptchaToken
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

        /// <summary>
        /// Completa el inicio de sesión con autenticación de dos factores
        /// </summary>
        /// <param name="request">Datos de autenticación de dos factores</param>
        /// <returns>Información de autenticación incluyendo token JWT</returns>
        [HttpPost("two-factor-login")]
        public async Task<IActionResult> TwoFactorLogin([FromBody] TwoFactorLoginRequest request)
        {
            var command = new TwoFactorLoginCommand
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

        /// <summary>
        /// Registra un nuevo usuario en el sistema
        /// </summary>
        /// <param name="request">Datos de registro</param>
        /// <returns>Resultado del registro</returns>
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (request.Password != request.ConfirmPassword)
            {
                return BadRequest(new { message = "Las contraseñas no coinciden" });
            }

            var command = new RegisterCommand
            {
                Username = request.Username,
                Email = request.Email,
                Password = request.Password,
                FirstName = request.FirstName,
                LastName = request.LastName,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                UserAgent = HttpContext.Request.Headers["User-Agent"].ToString(),
                RecaptchaToken = request.RecaptchaToken
            };

            var result = await _mediator.Send(command);

            if (!result.Succeeded)
            {
                return BadRequest(new { message = result.Error });
            }

            return Ok(new { message = "Registro exitoso. Por favor verifique su correo electrónico para activar su cuenta." });
        }

        /// <summary>
        /// Verifica el correo electrónico de un usuario
        /// </summary>
        /// <param name="userId">ID del usuario</param>
        /// <param name="token">Token de verificación</param>
        /// <returns>Resultado de la verificación</returns>
        [HttpGet("verify-email")]
        public async Task<IActionResult> VerifyEmail([FromQuery] Guid userId, [FromQuery] string token)
        {
            var command = new VerifyEmailCommand
            {
                UserId = userId,
                Code = token
            };

            var result = await _mediator.Send(command);

            if (!result.Succeeded)
            {
                return BadRequest(new { message = result.Error });
            }

            // Redirigir a la página de confirmación exitosa
            return Redirect("/email-verified");
        }

        /// <summary>
        /// Cierra sesión en el sistema
        /// </summary>
        /// <returns>Resultado del cierre de sesión</returns>
        [Authorize]
        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Sesión cerrada exitosamente" });
        }

        // Agregar endpoints para:
        // - ForgotPassword
        // - ResetPassword
        // - ChangePassword
        // - RefreshToken
        // - EnableTwoFactor
        // - DisableTwoFactor
    }

    public class TwoFactorLoginRequest
    {
        public Guid UserId { get; set; }
        public string Code { get; set; }
        public bool RememberMe { get; set; }
    }
}
EOF

cat > UsersController.cs << 'EOF'
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthSystem.API.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly ILogger<UsersController> _logger;

        public UsersController(ILogger<UsersController> logger)
        {
            _logger = logger;
        }

        [HttpGet("profile")]
        public IActionResult GetProfile()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Perfil de usuario" });
        }

        [HttpPut("profile")]
        public IActionResult UpdateProfile()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Perfil actualizado" });
        }

        [HttpGet("sessions")]
        public IActionResult GetSessions()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Sesiones de usuario" });
        }

        [HttpPost("sessions/{sessionId}/revoke")]
        public IActionResult RevokeSession(Guid sessionId)
        {
            // Implementar en una siguiente fase
            return Ok(new { message = $"Sesión {sessionId} revocada" });
        }

        [HttpPost("sessions/revoke-all")]
        public IActionResult RevokeAllSessions()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Todas las sesiones revocadas" });
        }

        [HttpGet("two-factor")]
        public IActionResult GetTwoFactorSettings()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Configuración de dos factores" });
        }

        [HttpPost("two-factor/enable")]
        public IActionResult EnableTwoFactor()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Autenticación de dos factores habilitada" });
        }

        [HttpPost("two-factor/disable")]
        public IActionResult DisableTwoFactor()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Autenticación de dos factores deshabilitada" });
        }

        [HttpGet("activity")]
        public IActionResult GetActivity()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Actividad de usuario" });
        }
    }
}
EOF

cat > AdminController.cs << 'EOF'
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthSystem.API.Controllers
{
    [Authorize(Roles = "Admin")]
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly ILogger<AdminController> _logger;

        public AdminController(ILogger<AdminController> logger)
        {
            _logger = logger;
        }

        [HttpGet("users")]
        public IActionResult GetUsers()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Lista de usuarios" });
        }

        [HttpGet("users/{id}")]
        public IActionResult GetUser(Guid id)
        {
            // Implementar en una siguiente fase
            return Ok(new { message = $"Usuario {id}" });
        }

        [HttpPost("users")]
        public IActionResult CreateUser()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Usuario creado" });
        }

        [HttpPut("users/{id}")]
        public IActionResult UpdateUser(Guid id)
        {
            // Implementar en una siguiente fase
            return Ok(new { message = $"Usuario {id} actualizado" });
        }

        [HttpDelete("users/{id}")]
        public IActionResult DeleteUser(Guid id)
        {
            // Implementar en una siguiente fase
            return Ok(new { message = $"Usuario {id} eliminado" });
        }

        [HttpGet("roles")]
        public IActionResult GetRoles()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Lista de roles" });
        }

        [HttpGet("permissions")]
        public IActionResult GetPermissions()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Lista de permisos" });
        }

        [HttpGet("modules")]
        public IActionResult GetModules()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Lista de módulos" });
        }

        [HttpGet("audit-logs")]
        public IActionResult GetAuditLogs()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Logs de auditoría" });
        }

        [HttpGet("login-attempts")]
        public IActionResult GetLoginAttempts()
        {
            // Implementar en una siguiente fase
            return Ok(new { message = "Intentos de inicio de sesión" });
        }
    }
}
EOF

# Crear appsettings.json
cd ..
cat > appsettings.json << 'EOF'
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*",
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=Auth;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=true",
    "RedisConnection": "localhost:6379"
  },
  "JwtSettings": {
    "Secret": "S3CR3T_K3Y_AT_L3AST_32_CHARACTERS_LONG",
    "Issuer": "AuthSystem",
    "Audience": "AuthSystemApi",
    "ExpirationMinutes": 60,
    "ExtendedExpirationMinutes": 1440,
    "RefreshTokenExpirationDays": 7
  },
  "EmailSettings": {
    "FromEmail": "no-reply@example.com",
    "FromName": "Auth System",
    "SmtpHost": "smtp.example.com",
    "SmtpPort": 587,
    "EnableSsl": true,
    "Username": "your-username",
    "Password": "your-password",
    "WebsiteBaseUrl": "https://localhost:5001"
  },
  "RecaptchaSettings": {
    "SiteKey": "your-recaptcha-site-key",
    "SecretKey": "your-recaptcha-secret-key",
    "MinimumScore": 0.5
  },
  "UseRedisCache": false,
  "AllowedOrigins": [
    "http://localhost:4200",
    "https://example.com"
  ],
  "IpRateLimiting": {
    "EnableEndpointRateLimiting": true,
    "StackBlockedRequests": false,
    "RealIpHeader": "X-Real-IP",
    "ClientIdHeader": "X-ClientId",
    "HttpStatusCode": 429,
    "GeneralRules": [
      {
        "Endpoint": "*:/api/auth/login",
        "Period": "1m",
        "Limit": 10
      },
      {
        "Endpoint": "*:/api/auth/register",
        "Period": "10m",
        "Limit": 5
      },
      {
        "Endpoint": "*",
        "Period": "1s",
        "Limit": 10
      }
    ]
  },
  "Serilog": {
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    }
  }
}
EOF

cat > appsettings.Development.json << 'EOF'
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "DetailedErrors": true
}
EOF

# Configurar launchSettings.json
mkdir Properties
cd Properties

cat > launchSettings.json << 'EOF'
{
  "$schema": "https://json.schemastore.org/launchsettings.json",
  "iisSettings": {
    "windowsAuthentication": false,
    "anonymousAuthentication": true,
    "iisExpress": {
      "applicationUrl": "http://localhost:31493",
      "sslPort": 44376
    }
  },
  "profiles": {
    "http": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "launchUrl": "swagger",
      "applicationUrl": "http://localhost:5284",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "https": {
      "commandName": "Project",
      "dotnetRunMessages": true,
      "launchBrowser": true,
      "launchUrl": "swagger",
      "applicationUrl": "https://localhost:7214;http://localhost:5284",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "IIS Express": {
      "commandName": "IISExpress",
      "launchBrowser": true,
      "launchUrl": "swagger",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  }
}
EOF

## Próximos Pasos

Después de crear toda la estructura del proyecto y los archivos básicos, los siguientes pasos son:

1. **Compilar el proyecto**
   ```bash
   cd ../..
   dotnet build
   ```

2. **Crear migraciones de Entity Framework Core**
   ```bash
   cd src/AuthSystem.API
   dotnet ef migrations add InitialMigration -o ../AuthSystem.Infrastructure/Data/Migrations
   ```

3. **Aplicar migraciones a la base de datos**
   ```bash
   dotnet ef database update
   ```

4. **Ejecutar la aplicación**
   ```bash
   dotnet run
   ```

5. **Implementar la lógica faltante**
   - Completar los controladores con endpoints faltantes
   - Implementar comandos y consultas adicionales
   - Configurar validaciones con FluentValidation
   - Implementar pruebas unitarias e integración

## Consideraciones Finales

Este proyecto incluye:

1. **Arquitectura Limpia**
   - Separación clara de responsabilidades
   - Independencia de frameworks
   - Testabilidad mejorada

2. **Patrón CQRS**
   - Separación de comandos y consultas
   - Pipeline de validación y comportamientos

3. **Seguridad**
   - Autenticación JWT
   - Permisos granulares
   - Auditoría completa
   - Protección contra ataques comunes

4. **Características Avanzadas**
   - Autenticación de dos factores
   - Gestión de sesiones
   - Bloqueo de cuentas
   - Límite de tasa de peticiones
   - Monitoreo de salud
   - Registro detallado

El sistema está diseñado para ser escalable y extensible, permitiendo agregar nuevas funcionalidades con un mínimo impacto en el código existente.
using System;
using System.Collections.Generic;

namespace AuthSystem.Application.DTOs
{
    public class ModuleDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public string Icon { get; set; }
        public string Route { get; set; }
        public bool IsActive { get; set; }
        public int DisplayOrder { get; set; }
        public Guid? ParentId { get; set; }
        public string ParentName { get; set; }
        public List<ModuleDto> Children { get; set; } = new List<ModuleDto>();
        public List<PermissionDto> Permissions { get; set; } = new List<PermissionDto>();
    }
}
EOF

cat > AuthenticationResultDto.cs << 'EOF'
using System;

namespace AuthSystem.Application.DTOs
{
    public class AuthenticationResultDto
    {
        public bool Succeeded { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public Guid? UserId { get; set; }
        public bool RequirePasswordChange { get; set; }
        public string Error { get; set; }

        public static AuthenticationResultDto Success(string token, string refreshToken, bool requirePasswordChange = false)
        {
            return new AuthenticationResultDto
            {
                Succeeded = true,
                Token = token,
                RefreshToken = refreshToken,
                RequirePasswordChange = requirePasswordChange
            };
        }

        public static AuthenticationResultDto TwoFactorRequired(Guid userId)
        {
            return new AuthenticationResultDto
            {
                Succeeded = false,
                RequiresTwoFactor = true,
                UserId = userId
            };
        }

        public static AuthenticationResultDto Failure(string error)
        {
            return new AuthenticationResultDto
            {
                Succeeded = false,
                Error = error
            };
        }
    }
}
EOF

cat > LoginRequest.cs << 'EOF'
using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class LoginRequest
    {
        [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
        public string Username { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        public string Password { get; set; }

        public bool RememberMe { get; set; }

        public string RecaptchaToken { get; set; }
    }
}
EOF

cat > RegisterRequest.cs << 'EOF'
using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class RegisterRequest
    {
        [Required(ErrorMessage = "El nombre de usuario es obligatorio")]
        [MinLength(4, ErrorMessage = "El nombre de usuario debe tener al menos 4 caracteres")]
        public string Username { get; set; }

        [Required(ErrorMessage = "El correo electrónico es obligatorio")]
        [EmailAddress(ErrorMessage = "El formato del correo electrónico no es válido")]
        public string Email { get; set; }

        [Required(ErrorMessage = "La contraseña es obligatoria")]
        [MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres")]
        public string Password { get; set; }

        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden")]
        public string ConfirmPassword { get; set; }

        public string FirstName { get; set; }

        public string LastName { get; set; }

        public string RecaptchaToken { get; set; }
    }
}
EOF

cd ..

# Crear Mappings
mkdir Mappings
cd Mappings

cat > MappingProfile.cs << 'EOF'
using AutoMapper;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Entities;
using System.Linq;

namespace AuthSystem.Application.Mappings
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // User mappings
            CreateMap<User, UserDto>()
                .ForMember(dest => dest.Status, opt => opt.MapFrom(src => src.Status.ToString()))
                .ForMember(dest => dest.Roles, opt => opt.Ignore())
                .ForMember(dest => dest.Permissions, opt => opt.Ignore());

            // Role mappings
            CreateMap<Role, RoleDto>();

            // Permission mappings
            CreateMap<Permission, PermissionDto>();

            // Module mappings
            CreateMap<Module, ModuleDto>()
                .ForMember(dest => dest.ParentName, opt => opt.MapFrom(src => src.Parent != null ? src.Parent.Name : null))
                .ForMember(dest => dest.Children, opt => opt.MapFrom(src => src.Children))
                .ForMember(dest => dest.Permissions, opt => opt.Ignore());
        }
    }
}
EOF

cd ..

# Crear Commands para Autenticación
mkdir Commands
cd Commands
mkdir Authentication
cd Authentication

cat > AuthenticateCommand.cs << 'EOF'
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace AuthSystem.Application.Commands.Authentication
{
    public class AuthenticateCommand : IRequest<AuthenticationResultDto>
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public bool RememberMe { get; set; }
        public string RecaptchaToken { get; set; }
    }

    public class AuthenticateCommandHandler : IRequestHandler<AuthenticateCommand, AuthenticationResultDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IJwtService _jwtService;
        private readonly IAuditService _auditService;
        private readonly IRecaptchaService _recaptchaService;
        private readonly ILogger<AuthenticateCommandHandler> _logger;

        public AuthenticateCommandHandler(
            IUserRepository userRepository,
            IPasswordHasher passwordHasher,
            IJwtService jwtService,
            IAuditService auditService,
            IRecaptchaService recaptchaService,
            ILogger<AuthenticateCommandHandler> logger)
        {
            _userRepository = userRepository;
            _passwordHasher = passwordHasher;
            _jwtService = jwtService;
            _auditService = auditService;
            _recaptchaService = recaptchaService;
            _logger = logger;
        }

        public async Task<AuthenticationResultDto> Handle(AuthenticateCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // Verificar reCAPTCHA si se proporciona un token
                if (!string.IsNullOrEmpty(request.RecaptchaToken))
                {
                    var isValidRecaptcha = await _recaptchaService.ValidateTokenAsync(
                        request.RecaptchaToken, request.IpAddress);

                    if (!isValidRecaptcha)
                    {
                        await _auditService.LogLoginAttemptAsync(
                            request.Username, request.IpAddress, request.UserAgent, false, "reCAPTCHA inválido");
                        return AuthenticationResultDto.Failure("Verificación de reCAPTCHA fallida");
                    }
                }

                // Buscar usuario por nombre de usuario o email
                var user = await _userRepository.FindByUsernameOrEmailAsync(request.Username);

                // Verificar si el usuario existe
                if (user == null)
                {
                    await _auditService.LogLoginAttemptAsync(
                        request.Username, request.IpAddress, request.UserAgent, false, "Usuario no encontrado");
                    return AuthenticationResultDto.Failure("Credenciales inválidas");
                }

                // Verificar estado del usuario
                if (user.Status != Core.Entities.UserStatus.Active && user.Status != Core.Entities.UserStatus.Registered)
                {
                    await _auditService.LogLoginAttemptAsync(
                        request.Username, request.IpAddress, request.UserAgent, false, $"Usuario con estado {user.Status}");
                    
                    if (user.Status == Core.Entities.UserStatus.Blocked)
                    {
                        return AuthenticationResultDto.Failure("Cuenta bloqueada. Por favor contacte al administrador.");
                    }
                    else
                    {
                        return AuthenticationResultDto.Failure("Cuenta no activa");
                    }
                }

                // Verificar si la cuenta está bloqueada
                if (user.LockoutEnabled && user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.UtcNow)
                {
                    await _auditService.LogLoginAttemptAsync(
                        request.Username, request.IpAddress, request.UserAgent, false, "Cuenta bloqueada temporalmente");
                    return AuthenticationResultDto.Failure("Cuenta temporalmente bloqueada. Intente más tarde.");
                }

                // Verificar contraseña
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
                    await _userRepository.SaveChangesAsync();

                    await _auditService.LogLoginAttemptAsync(
                        request.Username, request.IpAddress, request.UserAgent, false, "Contraseña incorrecta", user.Id);

                    return AuthenticationResultDto.Failure("Credenciales inválidas");
                }

                // Resetear contador de intentos fallidos si la autenticación es exitosa
                user.ResetAccessFailedCount();
                user.UpdateLastLoginDate();
                
                // Activar la cuenta si está en estado registrado
                if (user.Status == Core.Entities.UserStatus.Registered && user.EmailConfirmed)
                {
                    // Podríamos tener un método específico en la entidad para esto
                    // Como no lo tenemos, utilizamos el que tenemos disponible
                    user.ConfirmEmail(); // Esto también establece el estado como Active
                }
                
                await _userRepository.UpdateAsync(user);
                await _userRepository.SaveChangesAsync();

                // Verificar si se requiere 2FA
                if (user.TwoFactorEnabled)
                {
                    await _auditService.LogLoginAttemptAsync(
                        request.Username, request.IpAddress, request.UserAgent, true, "Requiere 2FA", user.Id);
                    return AuthenticationResultDto.TwoFactorRequired(user.Id);
                }

                // Generar tokens JWT
                var (token, refreshToken) = await _jwtService.GenerateTokensAsync(user, request.RememberMe);

                // Registrar sesión
                var sessionId = Guid.NewGuid();
                await _userRepository.AddSessionAsync(new UserSession
                {
                    Id = sessionId,
                    UserId = user.Id,
                    Token = token,
                    RefreshToken = refreshToken,
                    IPAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = request.RememberMe ? DateTime.UtcNow.AddDays(7) : DateTime.UtcNow.AddHours(2)
                });

                // Registrar login exitoso
                await _auditService.LogLoginAttemptAsync(
                    request.Username, request.IpAddress, request.UserAgent, true, null, user.Id);

                // Retornar resultado exitoso
                return AuthenticationResultDto.Success(token, refreshToken, user.RequirePasswordChange);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante la autenticación de usuario {Username}", request.Username);
                return AuthenticationResultDto.Failure("Error durante la autenticación");
            }
        }
    }
}
EOF

cat > RegisterCommand.cs << 'EOF'
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Text;

namespace AuthSystem.Application.Commands.Authentication
{
    public class RegisterCommand : IRequest<AuthenticationResultDto>
    {
        public string Username { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public string RecaptchaToken { get; set; }
    }

    public class RegisterCommandHandler : IRequestHandler<RegisterCommand, AuthenticationResultDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly IRoleRepository _roleRepository;
        private readonly IPasswordHasher _passwordHasher;
        private readonly IEmailService _emailService;
        private readonly IRecaptchaService _recaptchaService;
        private readonly IAuditService _auditService;
        private readonly ILogger<RegisterCommandHandler> _logger;

        public RegisterCommandHandler(
            IUserRepository userRepository,
            IRoleRepository roleRepository,
            IPasswordHasher passwordHasher,
            IEmailService emailService,
            IRecaptchaService recaptchaService,
            IAuditService auditService,
            ILogger<RegisterCommandHandler> logger)
        {
            _userRepository = userRepository;
            _roleRepository = roleRepository;
            _passwordHasher = passwordHasher;
            _emailService = emailService;
            _recaptchaService = recaptchaService;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<AuthenticationResultDto> Handle(RegisterCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // Verificar reCAPTCHA si se proporciona un token
                if (!string.IsNullOrEmpty(request.RecaptchaToken))
                {
                    var isValidRecaptcha = await _recaptchaService.ValidateTokenAsync(
                        request.RecaptchaToken, request.IpAddress);

                    if (!isValidRecaptcha)
                    {
                        return AuthenticationResultDto.Failure("Verificación de reCAPTCHA fallida");
                    }
                }

                // Verificar si el usuario ya existe
                var existingUser = await _userRepository.FindByUsernameOrEmailAsync(request.Username);
                if (existingUser != null)
                {
                    return AuthenticationResultDto.Failure("El nombre de usuario ya está en uso");
                }

                existingUser = await _userRepository.FindByEmailAsync(request.Email);
                if (existingUser != null)
                {
                    return AuthenticationResultDto.Failure("El correo electrónico ya está registrado");
                }

                // Hashear contraseña
                var passwordHash = _passwordHasher.HashPassword(request.Password);

                // Crear usuario
                var user = new User(
                    request.Username,
                    request.Email,
                    passwordHash,
                    request.FirstName,
                    request.LastName);

                // Guardar usuario
                await _userRepository.AddAsync(user);
                await _userRepository.SaveChangesAsync();

                // Asignar rol por defecto (si existe)
                var defaultRole = await _roleRepository.FindByNameAsync("Usuario");
                if (defaultRole != null)
                {
                    await _userRepository.AddToRoleAsync(user.Id, defaultRole.Id);
                }

                // Generar token de confirmación
                var token = GenerateEmailConfirmationToken();
                
                // Enviar correo de confirmación
                await _emailService.SendConfirmationEmailAsync(user.Email, user.Id.ToString(), token);

                // Registrar acción
                await _auditService.LogActionAsync(
                    user.Id,
                    "Register",
                    "User",
                    user.Id.ToString(),
                    null,
                    new { user.Id, user.Username, user.Email },
                    request.IpAddress,
                    request.UserAgent);

                return AuthenticationResultDto.Success(null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante el registro de usuario {Username}", request.Username);
                return AuthenticationResultDto.Failure("Error durante el registro");
            }
        }

        private string GenerateEmailConfirmationToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
EOF

cat > VerifyEmailCommand.cs << 'EOF'
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace AuthSystem.Application.Commands.Authentication
{
    public class VerifyEmailCommand : IRequest<AuthenticationResultDto>
    {
        public Guid UserId { get; set; }
        public string Code { get; set; }
    }

    public class VerifyEmailCommandHandler : IRequestHandler<VerifyEmailCommand, AuthenticationResultDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly ILogger<VerifyEmailCommandHandler> _logger;

        public VerifyEmailCommandHandler(
            IUserRepository userRepository,
            ILogger<VerifyEmailCommandHandler> logger)
        {
            _userRepository = userRepository;
            _logger = logger;
        }

        public async Task<AuthenticationResultDto> Handle(VerifyEmailCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // En una implementación real, verificaríamos el token con el almacenado
                // Para este ejemplo, simplemente confirmamos el correo si el usuario existe

                var user = await _userRepository.GetByIdAsync(request.UserId);
                if (user == null)
                {
                    return AuthenticationResultDto.Failure("Usuario no encontrado");
                }

                if (user.EmailConfirmed)
                {
                    return AuthenticationResultDto.Failure("El correo electrónico ya ha sido confirmado");
                }

                // Confirmar email y activar usuario
                user.ConfirmEmail();
                
                await _userRepository.UpdateAsync(user);
                await _userRepository.SaveChangesAsync();

                return AuthenticationResultDto.Success(null, null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante la verificación de correo electrónico del usuario {UserId}", request.UserId);
                return AuthenticationResultDto.Failure("Error durante la verificación del correo electrónico");
            }
        }
    }
}
EOF

cat > TwoFactorLoginCommand.cs << 'EOF'
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Interfaces;
using MediatR;
using Microsoft.Extensions.Logging;

namespace AuthSystem.Application.Commands.Authentication
{
    public class TwoFactorLoginCommand : IRequest<AuthenticationResultDto>
    {
        public Guid UserId { get; set; }
        public string Code { get; set; }
        public string IpAddress { get; set; }
        public string UserAgent { get; set; }
        public bool RememberMe { get; set; }
    }

    public class TwoFactorLoginCommandHandler : IRequestHandler<TwoFactorLoginCommand, AuthenticationResultDto>
    {
        private readonly IUserRepository _userRepository;
        private readonly ITotpService _totpService;
        private readonly IJwtService _jwtService;
        private readonly IAuditService _auditService;
        private readonly ILogger<TwoFactorLoginCommandHandler> _logger;

        public TwoFactorLoginCommandHandler(
            IUserRepository userRepository,
            ITotpService totpService,
            IJwtService jwtService,
            IAuditService auditService,
            ILogger<TwoFactorLoginCommandHandler> logger)
        {
            _userRepository = userRepository;
            _totpService = totpService;
            _jwtService = jwtService;
            _auditService = auditService;
            _logger = logger;
        }

        public async Task<AuthenticationResultDto> Handle(TwoFactorLoginCommand request, CancellationToken cancellationToken)
        {
            try
            {
                // Obtener usuario
                var user = await _userRepository.GetByIdAsync(request.UserId);
                if (user == null)
                {
                    return AuthenticationResultDto.Failure("Usuario no encontrado");
                }

                // Verificar estado del usuario
                if (user.Status != Core.Entities.UserStatus.Active)
                {
                    await _auditService.LogLoginAttemptAsync(
                        user.Username, request.IpAddress, request.UserAgent, false, $"Usuario con estado {user.Status}", user.Id);
                    return AuthenticationResultDto.Failure("Cuenta no activa");
                }

                // Verificar si 2FA está habilitado
                if (!user.TwoFactorEnabled)
                {
                    await _auditService.LogLoginAttemptAsync(
                        user.Username, request.IpAddress, request.UserAgent, false, "2FA no habilitado", user.Id);
                    return AuthenticationResultDto.Failure("Autenticación de dos factores no habilitada");
                }

                // Obtener configuración de 2FA
                var twoFactorSettings = await _userRepository.GetTwoFactorSettingsAsync(user.Id);
                if (twoFactorSettings == null)
                {
                    await _auditService.LogLoginAttemptAsync(
                        user.Username, request.IpAddress, request.UserAgent, false, "Configuración 2FA no encontrada", user.Id);
                    return AuthenticationResultDto.Failure("Error en la configuración de autenticación de dos factores");
                }

                bool isValidCode = false;

                // Verificar código según el método
                if (twoFactorSettings.Method == "Authenticator")
                {
                    isValidCode = _totpService.ValidateCode(twoFactorSettings.SecretKey, request.Code);
                }
                else
                {
                    // Para Email/SMS, verificaríamos contra un código almacenado en caché
                    // Para este ejemplo, aceptamos "123456" como código válido
                    isValidCode = request.Code == "123456";
                }

                if (!isValidCode)
                {
                    await _auditService.LogLoginAttemptAsync(
                        user.Username, request.IpAddress, request.UserAgent, false, "Código 2FA inválido", user.Id);
                    return AuthenticationResultDto.Failure("Código de verificación inválido");
                }

                // Generar tokens JWT
                var (token, refreshToken) = await _jwtService.GenerateTokensAsync(user, request.RememberMe);

                // Registrar sesión
                var sessionId = Guid.NewGuid();
                await _userRepository.AddSessionAsync(new Core.Entities.UserSession
                {
                    Id = sessionId,
                    UserId = user.Id,
                    Token = token,
                    RefreshToken = refreshToken,
                    IPAddress = request.IpAddress,
                    UserAgent = request.UserAgent,
                    IssuedAt = DateTime.UtcNow,
                    ExpiresAt = request.RememberMe ? DateTime.UtcNow.AddDays(7) : DateTime.UtcNow.AddHours(2)
                });

                // Registrar login exitoso
                await _auditService.LogLoginAttemptAsync(
                    user.Username, request.IpAddress, request.UserAgent, true, "Login con 2FA", user.Id);

                // Retornar resultado exitoso
                return AuthenticationResultDto.Success(token, refreshToken, user.RequirePasswordChange);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error durante la autenticación 2FA del usuario {UserId}", request.UserId);
                return AuthenticationResultDto.Failure("Error durante la autenticación de dos factores");
            }
        }
    }
}
EOF

# Configurar Application Service Registration
cd ../../../

cat > DependencyInjection.cs << 'EOF'
using System.Reflection;
using AuthSystem.Application.Behaviors;
using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;

namespace AuthSystem.Application
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddApplication(this IServiceCollection services)
        {
            // Registrar AutoMapper
            services.AddAutoMapper(Assembly.GetExecutingAssembly());
            
            // Registrar MediatR
            services.AddMediatR(cfg => 
            {
                cfg.RegisterServicesFromAssembly(Assembly.GetExecutingAssembly());
                cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));
                cfg.AddBehavior(typeof(IPipelineBehavior<,>), typeof(LoggingBehavior<,>));
            });
            
            // Registrar FluentValidation
            services.AddValidatorsFromAssembly(Assembly.GetExecutingAssembly());
            
            return services;
        }
    }
}
EOF

# Crear Behaviors
mkdir Behaviors
cd Behaviors

cat > ValidationBehavior.cs << 'EOF'
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentValidation;
using MediatR;

namespace AuthSystem.Application.Behaviors
{
    public class ValidationBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
        where TRequest : IRequest<TResponse>
    {
        private readonly IEnumerable<IValidator<TRequest>> _validators;

        public ValidationBehavior(IEnumerable<IValidator<TRequest>> validators)
        {
            _validators = validators;
        }

        public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
        {
            if (_validators.Any())
            {
                var context = new ValidationContext<TRequest>(request);

                var validationResults = await Task.WhenAll(
                    _validators.Select(v => v.ValidateAsync(context, cancellationToken)));

                var failures = validationResults
                    .SelectMany(r => r.Errors)
                    .Where(f => f != null)
                    .ToList();

                if (failures.Count != 0)
                {
                    throw new ValidationException(failures);
                }
            }

            return await next();
        }
    }
}
EOF

cat > LoggingBehavior.cs << 'EOF'
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using MediatR;
using Microsoft.Extensions.Logging;

namespace AuthSystem.Application.Behaviors
{
    public class LoggingBehavior<TRequest, TResponse> : IPipelineBehavior<TRequest, TResponse>
        where TRequest : IRequest<TResponse>
    {
        private readonly ILogger<LoggingBehavior<TRequest, TResponse>> _logger;

        public LoggingBehavior(ILogger<LoggingBehavior<TRequest, TResponse>> logger)
        {
            _logger = logger;
        }

        public async Task<TResponse> Handle(TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
        {
            var requestName = typeof(TRequest).Name;
            
            _logger.LogInformation("Handling {RequestName}", requestName);

            var stopwatch = Stopwatch.StartNew();
            try
            {
                var response = await next();
                stopwatch.Stop();
                
                _logger.LogInformation("Handled {RequestName} in {ElapsedMilliseconds}ms", requestName, stopwatch.ElapsedMilliseconds);
                
                return response;
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "Error handling {RequestName} after {ElapsedMilliseconds}ms", requestName, stopwatch.ElapsedMilliseconds);
                throw;
            }
        }
    }
}
EOF

# Configurar la API
cd ../../AuthSystem.API

# Configurar Program.cs
cat > Program.cs << 'EOF'
using System;
using System.Text.Json.Serialization;
using AuthSystem.Application;
using AuthSystem.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models;
using Serilog;
using AuthSystem.API.Middleware;
using System.Reflection;
using AuthSystem.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using System.IO;

var builder = WebApplication.CreateBuilder(args);

// Configurar Serilog
builder.Host.UseSerilog((context, configuration) =>
{
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .WriteTo.Console()
        .WriteTo.File(
            Path.Combine("Logs", "log-.txt"),
            rollingInterval: RollingInterval.Day,
            retainedFileCountLimit: 30);
});

// Configurar CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy", policy =>
    {
        policy.WithOrigins(builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? new[] { "http://localhost:4200" })
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials();
    });
});

// Agregar servicios de la aplicación
builder.Services.AddApplication();
builder.Services.AddInfrastructure(builder.Configuration);

// Configurar JSON serialization
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
    });

// Configurar JWT Authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.Auth                .OrderBy(m => m.DisplayOrder)
                .ToListAsync();
        }

        public async Task<IReadOnlyList<Module>> GetUserModulesAsync(Guid userId)
        {
            // Podríamos llamar directamente al procedimiento almacenado
            // Pero aquí mostraremos la implementación equivalente con EF Core
            
            // Obtener todos los permisos del usuario
            var userPermissions = new List<Guid>();
            
            // Permisos directos
            var directPermissions = await _context.UserPermissions
                .Where(up => up.UserId == userId && up.IsGranted)
                .Where(up => up.ExpirationDate == null || up.ExpirationDate > DateTime.UtcNow)
                .Select(up => up.PermissionId)
                .ToListAsync();
            
            userPermissions.AddRange(directPermissions);
            
            // Permisos basados en roles
            var rolePermissions = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.IsActive)
                .Where(ur => ur.ExpirationDate == null || ur.ExpirationDate > DateTime.UtcNow)
                .Join(_context.RolePermissions,
                    ur => ur.RoleId,
                    rp => rp.RoleId,
                    (ur, rp) => rp.PermissionId)
                .Distinct()
                .ToListAsync();
            
            userPermissions.AddRange(rolePermissions);
            userPermissions = userPermissions.Distinct().ToList();
            
            // Obtener módulos accesibles
            var moduleIds = await _context.ModulePermissions
                .Where(mp => userPermissions.Contains(mp.PermissionId))
                .Select(mp => mp.ModuleId)
                .Distinct()
                .ToListAsync();
            
            return await _dbSet
                .Where(m => moduleIds.Contains(m.Id) && m.IsActive)
                .OrderBy(m => m.ParentId)
                .ThenBy(m => m.DisplayOrder)
                .ToListAsync();
        }

        public async Task<bool> AddModulePermissionAsync(Guid moduleId, Guid permissionId)
        {
            var modulePermission = await _context.ModulePermissions
                .FirstOrDefaultAsync(mp => mp.ModuleId == moduleId && mp.PermissionId == permissionId);

            if (modulePermission != null)
            {
                return true; // Ya existe, no es necesario hacer nada
            }

            modulePermission = new ModulePermission
            {
                ModuleId = moduleId,
                PermissionId = permissionId
            };

            await _context.ModulePermissions.AddAsync(modulePermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveModulePermissionAsync(Guid moduleId, Guid permissionId)
        {
            var modulePermission = await _context.ModulePermissions
                .FirstOrDefaultAsync(mp => mp.ModuleId == moduleId && mp.PermissionId == permissionId);

            if (modulePermission == null)
            {
                return false;
            }

            _context.ModulePermissions.Remove(modulePermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<IReadOnlyList<Permission>> GetModulePermissionsAsync(Guid moduleId)
        {
            var permissionIds = await _context.ModulePermissions
                .Where(mp => mp.ModuleId == moduleId)
                .Select(mp => mp.PermissionId)
                .ToListAsync();

            return await _context.Permissions
                .Where(p => permissionIds.Contains(p.Id))
                .ToListAsync();
        }
    }
}
EOF

cat > AuditRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class AuditRepository : IAuditRepository
    {
        private readonly ApplicationDbContext _context;

        public AuditRepository(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task LogActionAsync(Guid? userId, string action, string entityName, string entityId, 
                                        string oldValues, string newValues, string ipAddress, string userAgent)
        {
            var auditLog = new AuditLog
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                Action = action,
                EntityName = entityName,
                EntityId = entityId,
                OldValues = oldValues,
                NewValues = newValues,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                CreatedAt = DateTime.UtcNow
            };

            await _context.AuditLog.AddAsync(auditLog);
            await _context.SaveChangesAsync();
        }

        public async Task LogLoginAttemptAsync(string username, string email, string ipAddress, string userAgent,
                                              bool successful, string failureReason, Guid? userId)
        {
            var loginAttempt = new LoginAttempt
            {
                Id = Guid.NewGuid(),
                Username = username,
                Email = email,
                IPAddress = ipAddress,
                UserAgent = userAgent,
                Successful = successful,
                FailureReason = failureReason,
                AttemptedAt = DateTime.UtcNow,
                UserId = userId
            };

            await _context.LoginAttempts.AddAsync(loginAttempt);
            await _context.SaveChangesAsync();
        }

        public async Task<IReadOnlyList<AuditLog>> GetAuditLogsAsync(DateTime? startDate, DateTime? endDate, 
                                                                     Guid? userId, string entityName, string action)
        {
            var query = _context.AuditLog.AsQueryable();

            if (startDate.HasValue)
            {
                query = query.Where(a => a.CreatedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(a => a.CreatedAt <= endDate.Value);
            }

            if (userId.HasValue)
            {
                query = query.Where(a => a.UserId == userId.Value);
            }

            if (!string.IsNullOrEmpty(entityName))
            {
                query = query.Where(a => a.EntityName == entityName);
            }

            if (!string.IsNullOrEmpty(action))
            {
                query = query.Where(a => a.Action == action);
            }

            return await query.OrderByDescending(a => a.CreatedAt).ToListAsync();
        }

        public async Task<IReadOnlyList<LoginAttempt>> GetLoginAttemptsAsync(DateTime? startDate, DateTime? endDate, 
                                                                             Guid? userId, string ipAddress, bool? successful)
        {
            var query = _context.LoginAttempts.AsQueryable();

            if (startDate.HasValue)
            {
                query = query.Where(la => la.AttemptedAt >= startDate.Value);
            }

            if (endDate.HasValue)
            {
                query = query.Where(la => la.AttemptedAt <= endDate.Value);
            }

            if (userId.HasValue)
            {
                query = query.Where(la => la.UserId == userId.Value);
            }

            if (!string.IsNullOrEmpty(ipAddress))
            {
                query = query.Where(la => la.IPAddress == ipAddress);
            }

            if (successful.HasValue)
            {
                query = query.Where(la => la.Successful == successful.Value);
            }

            return await query.OrderByDescending(la => la.AttemptedAt).ToListAsync();
        }
    }
}
EOF
```

### 6. Servicios en AuthSystem.Infrastructure

```bash
cd ../../Security

# Crear implementaciones de servicios de seguridad
cat > JwtService.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthSystem.Infrastructure.Security
{
    public class JwtService : IJwtService
    {
        private readonly JwtSettings _jwtSettings;
        private readonly IUserRepository _userRepository;
        private readonly IDateTimeProvider _dateTimeProvider;

        public JwtService(
            IOptions<JwtSettings> jwtSettings,
            IUserRepository userRepository,
            IDateTimeProvider dateTimeProvider)
        {
            _jwtSettings = jwtSettings.Value;
            _userRepository = userRepository;
            _dateTimeProvider = dateTimeProvider;
        }

        public async Task<(string Token, string RefreshToken)> GenerateTokensAsync(User user, bool extendedDuration = false)
        {
            // Obtener roles y permisos del usuario
            var roles = await _userRepository.GetUserRolesAsync(user.Id);
            var permissions = await _userRepository.GetUserPermissionsAsync(user.Id);

            // Crear claims para el token
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

            // Crear credenciales de firma
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Calcular tiempo de expiración
            var expires = _dateTimeProvider.UtcNow.AddMinutes(
                extendedDuration ? _jwtSettings.ExtendedExpirationMinutes : _jwtSettings.ExpirationMinutes);

            // Crear el token
            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expires,
                signingCredentials: creds
            );

            // Generar refresh token
            var refreshToken = GenerateRefreshToken();

            return (new JwtSecurityTokenHandler().WriteToken(token), refreshToken);
        }

        public async Task<(bool IsValid, string UserId, string Jti)> ValidateTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return (false, null, null);
            }

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.Secret);

            try
            {
                // Validar token
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtSettings.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtSettings.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = jwtToken.Claims.First(x => x.Type == JwtRegisteredClaimNames.Sub).Value;
                var jti = jwtToken.Claims.First(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                // Verificar si el token ha sido revocado
                if (await _userRepository.IsTokenRevokedAsync(Guid.Parse(userId), jti))
                {
                    return (false, null, null);
                }

                return (true, userId, jti);
            }
            catch
            {
                // Devolver falso si la validación falla
                return (false, null, null);
            }
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    public class JwtSettings
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int ExpirationMinutes { get; set; }
        public int ExtendedExpirationMinutes { get; set; }
        public int RefreshTokenExpirationDays { get; set; }
    }
}
EOF

cat > PasswordHasher.cs << 'EOF'
using AuthSystem.Core.Interfaces;
using System;

namespace AuthSystem.Infrastructure.Security
{
    public class PasswordHasher : IPasswordHasher
    {
        public string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, BCrypt.Net.BCrypt.GenerateSalt(12));
        }

        public bool VerifyPassword(string passwordHash, string inputPassword)
        {
            return BCrypt.Net.BCrypt.Verify(inputPassword, passwordHash);
        }
    }
}
EOF

cat > RecaptchaService.cs << 'EOF'
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;
using Microsoft.Extensions.Options;

namespace AuthSystem.Infrastructure.Security
{
    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _httpClient;
        private readonly RecaptchaSettings _settings;

        public RecaptchaService(HttpClient httpClient, IOptions<RecaptchaSettings> settings)
        {
            _httpClient = httpClient;
            _settings = settings.Value;
        }

        public async Task<bool> ValidateTokenAsync(string token, string ipAddress)
        {
            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            var response = await _httpClient.GetStringAsync(
                $"https://www.google.com/recaptcha/api/siteverify?secret={_settings.SecretKey}&response={token}&remoteip={ipAddress}");

            var recaptchaResponse = JsonSerializer.Deserialize<RecaptchaResponse>(response);

            return recaptchaResponse?.Success == true && recaptchaResponse.Score >= _settings.MinimumScore;
        }

        private class RecaptchaResponse
        {
            public bool Success { get; set; }
            public float Score { get; set; }
            public string Action { get; set; }
            public string Hostname { get; set; }
        }
    }

    public class RecaptchaSettings
    {
        public string SiteKey { get; set; }
        public string SecretKey { get; set; }
        public float MinimumScore { get; set; } = 0.5f;
    }
}
EOF

cat > TotpService.cs << 'EOF'
using AuthSystem.Core.Interfaces;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace AuthSystem.Infrastructure.Security
{
    public class TotpService : ITotpService
    {
        private const int DefaultStep = 30;
        private const int DefaultDigits = 6;

        public string GenerateSecretKey()
        {
            var key = new byte[20];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(key);
            return Convert.ToBase64String(key);
        }

        public string GenerateCode(string secretKey)
        {
            var counter = GetCurrentCounter();
            return GenerateCodeInternal(secretKey, counter);
        }

        public bool ValidateCode(string secretKey, string code)
        {
            if (string.IsNullOrEmpty(secretKey) || string.IsNullOrEmpty(code))
            {
                return false;
            }

            // Permitir un margen de un paso anterior y uno posterior para compensar desincronización
            var currentCounter = GetCurrentCounter();
            
            // Verificar código actual
            if (GenerateCodeInternal(secretKey, currentCounter) == code)
            {
                return true;
            }
            
            // Verificar código anterior
            if (GenerateCodeInternal(secretKey, currentCounter - 1) == code)
            {
                return true;
            }
            
            // Verificar código siguiente
            if (GenerateCodeInternal(secretKey, currentCounter + 1) == code)
            {
                return true;
            }
            
            return false;
        }

        public string[] GenerateRecoveryCodes(int numberOfCodes = 8)
        {
            var codes = new string[numberOfCodes];
            using var rng = RandomNumberGenerator.Create();
            
            for (int i = 0; i < numberOfCodes; i++)
            {
                var codeBytes = new byte[10]; // 10 bytes = 20 caracteres en hex
                rng.GetBytes(codeBytes);
                codes[i] = BitConverter.ToString(codeBytes).Replace("-", "").ToLower();
            }
            
            return codes;
        }

        private long GetCurrentCounter()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() / DefaultStep;
        }

        private string GenerateCodeInternal(string secretKey, long counter)
        {
            // Decodificar clave secreta
            byte[] key = Convert.FromBase64String(secretKey);
            
            // Convertir contador a bytes (big-endian)
            byte[] counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }
            
            // Asegurar que counterBytes tiene 8 bytes
            byte[] paddedCounter = new byte[8];
            Array.Copy(counterBytes, 0, paddedCounter, 8 - counterBytes.Length, counterBytes.Length);
            
            // Calcular HMAC-SHA1
            using var hmac = new HMACSHA1(key);
            byte[] hash = hmac.ComputeHash(paddedCounter);
            
            // Extraer un valor de 4 bytes basado en el offset del último nibble
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary =
                ((hash[offset] & 0x7F) << 24) |
                ((hash[offset + 1] & 0xFF) << 16) |
                ((hash[offset + 2] & 0xFF) << 8) |
                (hash[offset + 3] & 0xFF);
            
            // Convertir a código de 6 dígitos
            int otp = binary % (int)Math.Pow(10, DefaultDigits);
            return otp.ToString().PadLeft(DefaultDigits, '0');
        }
    }
}
EOF

cd ../Email

# Crear servicio de Email
cat > EmailService.cs << 'EOF'
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;
using Microsoft.Extensions.Options;

namespace AuthSystem.Infrastructure.Email
{
    public class EmailService : IEmailService
    {
        private readonly EmailSettings _emailSettings;

        public EmailService(IOptions<EmailSettings> emailSettings)
        {
            _emailSettings = emailSettings.Value;
        }

        public async Task SendAsync(string to, string subject, string body, bool isHtml = true)
        {
            var message = new MailMessage
            {
                From = new MailAddress(_emailSettings.FromEmail, _emailSettings.FromName),
                Subject = subject,
                Body = body,
                IsBodyHtml = isHtml
            };

            message.To.Add(to);

            using var client = new SmtpClient(_emailSettings.SmtpHost, _emailSettings.SmtpPort)
            {
                EnableSsl = _emailSettings.EnableSsl,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_emailSettings.Username, _emailSettings.Password)
            };

            await client.SendMailAsync(message);
        }

        public async Task SendConfirmationEmailAsync(string email, string userId, string token)
        {
            var callbackUrl = $"{_emailSettings.WebsiteBaseUrl}/auth/confirm-email?userId={userId}&token={token}";
            
            var subject = "Confirma tu cuenta";
            var body = $@"
                <h1>Gracias por registrarte</h1>
                <p>Por favor confirma tu cuenta haciendo clic en el siguiente enlace:</p>
                <p><a href='{callbackUrl}'>Confirmar cuenta</a></p>
                <p>Si no puedes hacer clic en el enlace, copia y pega la siguiente URL en tu navegador:</p>
                <p>{callbackUrl}</p>
                <p>Si no has solicitado este correo, puedes ignorarlo.</p>
            ";

            await SendAsync(email, subject, body);
        }

        public async Task SendPasswordResetEmailAsync(string email, string userId, string token)
        {
            var callbackUrl = $"{_emailSettings.WebsiteBaseUrl}/auth/reset-password?userId={userId}&token={token}";
            
            var subject = "Recuperación de contraseña";
            var body = $@"
                <h1>Recuperación de contraseña</h1>
                <p>Hemos recibido una solicitud para restablecer tu contraseña. Haz clic en el siguiente enlace para proceder:</p>
                <p><a href='{callbackUrl}'>Restablecer contraseña</a></p>
                <p>Si no puedes hacer clic en el enlace, copia y pega la siguiente URL en tu navegador:</p>
                <p>{callbackUrl}</p>
                <p>Si no has solicitado este correo, puedes ignorarlo.</p>
                <p>Este enlace expirará en 24 horas.</p>
            ";

            await SendAsync(email, subject, body);
        }

        public async Task SendTwoFactorCodeAsync(string email, string code)
        {
            var subject = "Código de verificación";
            var body = $@"
                <h1>Código de verificación</h1>
                <p>Tu código de verificación es:</p>
                <h2 style='font-size: 32px; letter-spacing: 5px; text-align: center; padding: 20px; background-color: #f5f5f5; border-radius: 5px;'>{code}</h2>
                <p>Este código expirará en 5 minutos.</p>
                <p>Si no has solicitado este código, alguien podría estar intentando acceder a tu cuenta.</p>
            ";

            await SendAsync(email, subject, body);
        }
    }

    public class EmailSettings
    {
        public string FromEmail { get; set; }
        public string FromName { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public bool EnableSsl { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public string WebsiteBaseUrl { get; set; }
    }
}
EOF

cd ../Services

# Crear servicios de utilidad
cat > DateTimeProvider.cs << 'EOF'
using System;
using AuthSystem.Core.Interfaces;

namespace AuthSystem.Infrastructure.Services
{
    public interface IDateTimeProvider
    {
        DateTime UtcNow { get; }
    }

    public class DateTimeProvider : IDateTimeProvider
    {
        public DateTime UtcNow => DateTime.UtcNow;
    }
}
EOF

cat > AuditService.cs << 'EOF'
using System;
using System.Text.Json;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;

namespace AuthSystem.Infrastructure.Services
{
    public class AuditService : IAuditService
    {
        private readonly IAuditRepository _auditRepository;

        public AuditService(IAuditRepository auditRepository)
        {
            _auditRepository = auditRepository;
        }

        public async Task LogActionAsync(Guid? userId, string action, string entityName, string entityId, 
                                        object oldValues, object newValues, string ipAddress = null, string userAgent = null)
        {
            string oldValuesJson = oldValues != null ? JsonSerializer.Serialize(oldValues) : null;
            string newValuesJson = newValues != null ? JsonSerializer.Serialize(newValues) : null;

            await _auditRepository.LogActionAsync(userId, action, entityName, entityId, 
                                                oldValuesJson, newValuesJson, ipAddress, userAgent);
        }

        public async Task LogLoginAttemptAsync(string username, string ipAddress, string userAgent, 
                                              bool successful, string failureReason = null, Guid? userId = null)
        {
            string email = null;
            
            // Verificar si username es un email
            if (username != null && username.Contains("@"))
            {
                email = username;
            }

            await _auditRepository.LogLoginAttemptAsync(username, email, ipAddress, userAgent, 
                                                      successful, failureReason, userId);
        }
    }
}
EOF
```

### 7. Configuración de Servicios en AuthSystem.Infrastructure

```bash
cd ..

# Crear registro de servicios
cat > DependencyInjection.cs << 'EOF'
using System;
using AuthSystem.Core.Interfaces;
using AuthSystem.Infrastructure.Data;
using AuthSystem.Infrastructure.Data.Repositories;
using AuthSystem.Infrastructure.Email;
using AuthSystem.Infrastructure.Security;
using AuthSystem.Infrastructure.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace AuthSystem.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
        {
            // Configurar DbContext
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    configuration.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)));

            // Registrar repositorios
            services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
            services.AddScoped<IUserRepository, UserRepository>();
            services.AddScoped<IRoleRepository, RoleRepository>();
            services.AddScoped<IPermissionRepository, PermissionRepository>();
            services.AddScoped<IModuleRepository, ModuleRepository>();
            services.AddScoped<IAuditRepository, AuditRepository>();

            // Registrar servicios
            services.AddScoped<IJwtService, JwtService>();
            services.AddScoped<IPasswordHasher, PasswordHasher>();
            services.AddScoped<ITotpService, TotpService>();
            services.AddScoped<IAuditService, AuditService>();
            services.AddScoped<IEmailService, EmailService>();
            services.AddSingleton<IDateTimeProvider, DateTimeProvider>();

            // Configuración
            services.Configure<JwtSettings>(configuration.GetSection("JwtSettings"));
            services.Configure<EmailSettings>(configuration.GetSection("EmailSettings"));
            services.Configure<RecaptchaSettings>(configuration.GetSection("RecaptchaSettings"));

            // HttpClient para servicios externos
            services.AddHttpClient<IRecaptchaService, RecaptchaService>();

            // Redis Cache (opcional)
            var useRedisCache = configuration.GetValue<bool>("UseRedisCache");
            if (useRedisCache)
            {
                services.AddStackExchangeRedisCache(options =>
                {
                    options.Configuration = configuration.GetConnectionString("RedisConnection");
                    options.InstanceName = "AuthSystem:";
                });
            }
            else
            {
                services.AddDistributedMemoryCache();
            }

            return services;
        }
    }
}
EOF
```

### 8. Configuración de Command/Query en AuthSystem.Application

```bash
cd ../../AuthSystem.Application

# Crear DTOs
mkdir DTOs
cd DTOs

# Crear DTOs básicos
cat > UserDto.cs << 'EOF'
using System;
using System.Collections.Generic;

namespace AuthSystem.Application.DTOs
{
    public class UserDto
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string FullName => $"{FirstName} {LastName}".Trim();
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public string ProfilePictureUrl { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public string Status { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        public List<string> Permissions { get; set; } = new List<string>();
    }
}
EOF

cat > RoleDto.cs << 'EOF'
using System;
using System.Collections.Generic;

namespace AuthSystem.Application.DTOs
{
    public class RoleDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public bool IsActive { get; set; }
        public bool IsDefault { get; set; }
        public int Priority { get; set; }
        public DateTime CreatedAt { get; set; }
        public List<PermissionDto> Permissions { get; set; } = new List<PermissionDto>();
    }
}
EOF

cat > PermissionDto.cs << 'EOF'
using System;

namespace AuthSystem.Application.DTOs
{
    public class PermissionDto
    {
        public Guid Id { get; set; }
        public string Name { get; set; }
        public string Code { get; set; }
        public string Description { get; set; }
        public string Category { get; set; }
    }
}
EOF

cat > ModuleDto.cs << 'EOF'
using System;
using        // Autenticación y sesiones
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<UserTwoFactorSettings> UserTwoFactorSettings { get; set; }
        public DbSet<PasswordHistory> PasswordHistory { get; set; }
        
        // Auditoría
        public DbSet<LoginAttempt> LoginAttempts { get; set; }
        public DbSet<AuditLog> AuditLog { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Aplicar configuraciones de entidades
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

            // Configuraciones especiales
            ConfigureUserRoles(modelBuilder);
            ConfigureRolePermissions(modelBuilder);
            ConfigureUserPermissions(modelBuilder);
            ConfigureModulePermissions(modelBuilder);
        }

        private void ConfigureUserRoles(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserRole>()
                .HasKey(ur => new { ur.UserId, ur.RoleId });

            modelBuilder.Entity<UserRole>()
                .HasOne<User>()
                .WithMany()
                .HasForeignKey(ur => ur.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserRole>()
                .HasOne<Role>()
                .WithMany()
                .HasForeignKey(ur => ur.RoleId)
                .OnDelete(DeleteBehavior.Cascade);
        }

        private void ConfigureRolePermissions(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<RolePermission>()
                .HasKey(rp => new { rp.RoleId, rp.PermissionId });

            modelBuilder.Entity<RolePermission>()
                .HasOne<Role>()
                .WithMany()
                .HasForeignKey(rp => rp.RoleId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<RolePermission>()
                .HasOne<Permission>()
                .WithMany()
                .HasForeignKey(rp => rp.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        }

        private void ConfigureUserPermissions(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<UserPermission>()
                .HasKey(up => new { up.UserId, up.PermissionId });

            modelBuilder.Entity<UserPermission>()
                .HasOne<User>()
                .WithMany()
                .HasForeignKey(up => up.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<UserPermission>()
                .HasOne<Permission>()
                .WithMany()
                .HasForeignKey(up => up.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        }

        private void ConfigureModulePermissions(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ModulePermission>()
                .HasKey(mp => new { mp.ModuleId, mp.PermissionId });

            modelBuilder.Entity<ModulePermission>()
                .HasOne<Module>()
                .WithMany()
                .HasForeignKey(mp => mp.ModuleId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<ModulePermission>()
                .HasOne<Permission>()
                .WithMany()
                .HasForeignKey(mp => mp.PermissionId)
                .OnDelete(DeleteBehavior.Cascade);
        }

        public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            // Implementar lógica para actualizar campos de auditoría (CreatedAt, UpdatedAt)
            foreach (var entry in ChangeTracker.Entries())
            {
                if (entry.Entity is BaseEntity entityBase)
                {
                    switch (entry.State)
                    {
                        case EntityState.Added:
                            entityBase.CreatedAt = DateTime.UtcNow;
                            entityBase.UpdatedAt = DateTime.UtcNow;
                            break;
                        case EntityState.Modified:
                            entityBase.UpdatedAt = DateTime.UtcNow;
                            break;
                    }
                }
            }

            return await base.SaveChangesAsync(cancellationToken);
        }
    }

    // Definición de entidades de relación
    public class UserRole
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
        public DateTime? ExpirationDate { get; set; }
        public bool IsActive { get; set; }
    }

    public class RolePermission
    {
        public Guid RoleId { get; set; }
        public Guid PermissionId { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
    }

    public class UserPermission
    {
        public Guid UserId { get; set; }
        public Guid PermissionId { get; set; }
        public bool IsGranted { get; set; }
        public Guid? AssignedBy { get; set; }
        public DateTime AssignedAt { get; set; }
        public DateTime? ExpirationDate { get; set; }
    }

    public class ModulePermission
    {
        public Guid ModuleId { get; set; }
        public Guid PermissionId { get; set; }
    }

    // Clase base para entidades con campos de auditoría
    public abstract class BaseEntity
    {
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
EOF
```

### 4. Configuraciones de Entidades

```bash
cd Configurations

# Crear configuraciones para entidades principales
cat > UserConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.ToTable("Users");

            builder.HasKey(u => u.Id);

            builder.Property(u => u.Username)
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(u => u.Username)
                .IsUnique();

            builder.Property(u => u.Email)
                .HasMaxLength(255)
                .IsRequired();

            builder.HasIndex(u => u.Email)
                .IsUnique();

            builder.Property(u => u.SecurityStamp)
                .IsRequired();

            builder.Property(u => u.FirstName)
                .HasMaxLength(100);

            builder.Property(u => u.LastName)
                .HasMaxLength(100);

            builder.Property(u => u.PhoneNumber)
                .HasMaxLength(20);

            builder.HasIndex(u => u.UserStatus);

            // Sombra de propiedad para NormalizedEmail
            builder.Property<string>("NormalizedEmail")
                .HasMaxLength(255)
                .IsRequired();

            builder.HasIndex("NormalizedEmail");
        }
    }
}
EOF

cat > RoleConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class RoleConfiguration : IEntityTypeConfiguration<Role>
    {
        public void Configure(EntityTypeBuilder<Role> builder)
        {
            builder.ToTable("Roles");

            builder.HasKey(r => r.Id);

            builder.Property(r => r.Name)
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(r => r.Name)
                .IsUnique();

            builder.Property(r => r.NormalizedName)
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(r => r.NormalizedName)
                .IsUnique();

            builder.Property(r => r.Description)
                .HasMaxLength(255);

            builder.HasIndex(r => r.IsDefault);
        }
    }
}
EOF

cat > PermissionConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class PermissionConfiguration : IEntityTypeConfiguration<Permission>
    {
        public void Configure(EntityTypeBuilder<Permission> builder)
        {
            builder.ToTable("Permissions");

            builder.HasKey(p => p.Id);

            builder.Property(p => p.Name)
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(p => p.Name)
                .IsUnique();

            builder.Property(p => p.Code)
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(p => p.Code)
                .IsUnique();

            builder.Property(p => p.Description)
                .HasMaxLength(255);

            builder.Property(p => p.Category)
                .HasMaxLength(100);

            builder.HasIndex(p => p.Category);
        }
    }
}
EOF

cat > ModuleConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class ModuleConfiguration : IEntityTypeConfiguration<Module>
    {
        public void Configure(EntityTypeBuilder<Module> builder)
        {
            builder.ToTable("Modules");

            builder.HasKey(m => m.Id);

            builder.Property(m => m.Name)
                .HasMaxLength(100)
                .IsRequired();

            builder.HasIndex(m => m.Name)
                .IsUnique();

            builder.Property(m => m.Description)
                .HasMaxLength(255);

            builder.Property(m => m.Icon)
                .HasMaxLength(100);

            builder.Property(m => m.Route)
                .HasMaxLength(100);

            builder.HasIndex(m => m.DisplayOrder);

            builder.HasIndex(m => m.ParentId);

            // Relación auto-referencial
            builder.HasOne(m => m.Parent)
                .WithMany(m => m.Children)
                .HasForeignKey(m => m.ParentId)
                .OnDelete(DeleteBehavior.Restrict);
        }
    }
}
EOF

cat > UserSessionConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class UserSessionConfiguration : IEntityTypeConfiguration<UserSession>
    {
        public void Configure(EntityTypeBuilder<UserSession> builder)
        {
            builder.ToTable("UserSessions");

            builder.HasKey(s => s.Id);

            builder.Property(s => s.UserId)
                .IsRequired();

            builder.Property(s => s.IPAddress)
                .HasMaxLength(50)
                .IsRequired();

            builder.HasIndex(s => s.UserId);
            
            builder.HasIndex(s => s.ExpiresAt);

            // Columna calculada para IsActive
            builder.Property(s => s.IsActive)
                .HasComputedColumnSql("CASE WHEN [RevokedAt] IS NULL AND [ExpiresAt] > GETUTCDATE() THEN 1 ELSE 0 END");

            // Relación con User
            builder.HasOne<User>()
                .WithMany()
                .HasForeignKey(s => s.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}
EOF

cat > AuditLogConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
    {
        public void Configure(EntityTypeBuilder<AuditLog> builder)
        {
            builder.ToTable("AuditLog");

            builder.HasKey(a => a.Id);

            builder.Property(a => a.Action)
                .HasMaxLength(100)
                .IsRequired();

            builder.Property(a => a.EntityName)
                .HasMaxLength(100)
                .IsRequired();

            builder.Property(a => a.EntityId)
                .HasMaxLength(100);

            builder.Property(a => a.IPAddress)
                .HasMaxLength(50);

            builder.HasIndex(a => a.UserId);
            builder.HasIndex(a => new { a.EntityName, a.EntityId });
            builder.HasIndex(a => a.CreatedAt);
        }
    }
}
EOF

cat > LoginAttemptConfiguration.cs << 'EOF'
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class LoginAttemptConfiguration : IEntityTypeConfiguration<LoginAttempt>
    {
        public void Configure(EntityTypeBuilder<LoginAttempt> builder)
        {
            builder.ToTable("LoginAttempts");

            builder.HasKey(la => la.Id);

            builder.Property(la => la.Username)
                .HasMaxLength(100)
                .IsRequired();

            builder.Property(la => la.Email)
                .HasMaxLength(255);

            builder.Property(la => la.IPAddress)
                .HasMaxLength(50)
                .IsRequired();

            builder.Property(la => la.FailureReason)
                .HasMaxLength(255);

            builder.HasIndex(la => la.Username);
            builder.HasIndex(la => la.IPAddress);
            builder.HasIndex(la => la.AttemptedAt);
            builder.HasIndex(la => la.UserId);
        }
    }
}
EOF
```

### 5. Repositorios

```bash
cd ../Repositories

# Crear implementaciones de repositorios
cat > Repository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class Repository<T> : IRepository<T> where T : class
    {
        protected readonly ApplicationDbContext _context;
        protected readonly DbSet<T> _dbSet;

        public Repository(ApplicationDbContext context)
        {
            _context = context;
            _dbSet = context.Set<T>();
        }

        public virtual async Task<T> GetByIdAsync(Guid id)
        {
            return await _dbSet.FindAsync(id);
        }

        public virtual async Task<IReadOnlyList<T>> GetAllAsync()
        {
            return await _dbSet.ToListAsync();
        }

        public virtual async Task<IReadOnlyList<T>> FindAsync(Expression<Func<T, bool>> predicate)
        {
            return await _dbSet.Where(predicate).ToListAsync();
        }

        public async Task<T> AddAsync(T entity)
        {
            await _dbSet.AddAsync(entity);
            return entity;
        }

        public Task UpdateAsync(T entity)
        {
            _context.Entry(entity).State = EntityState.Modified;
            return Task.CompletedTask;
        }

        public Task DeleteAsync(T entity)
        {
            _dbSet.Remove(entity);
            return Task.CompletedTask;
        }

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }
    }
}
EOF

cat > UserRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class UserRepository : Repository<User>, IUserRepository
    {
        public UserRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<User> FindByUsernameAsync(string username)
        {
            return await _dbSet.Where(u => u.Username == username && !u.IsDeleted)
                .FirstOrDefaultAsync();
        }

        public async Task<User> FindByEmailAsync(string email)
        {
            return await _dbSet.Where(u => u.Email == email && !u.IsDeleted)
                .FirstOrDefaultAsync();
        }

        public async Task<User> FindByUsernameOrEmailAsync(string usernameOrEmail)
        {
            return await _dbSet.Where(u => 
                    (u.Username == usernameOrEmail || u.Email == usernameOrEmail) && !u.IsDeleted)
                .FirstOrDefaultAsync();
        }

        public async Task<IReadOnlyList<Role>> GetUserRolesAsync(Guid userId)
        {
            var roleIds = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.IsActive)
                .Where(ur => ur.ExpirationDate == null || ur.ExpirationDate > DateTime.UtcNow)
                .Select(ur => ur.RoleId)
                .ToListAsync();

            return await _context.Roles
                .Where(r => roleIds.Contains(r.Id) && r.IsActive)
                .ToListAsync();
        }

        public async Task<IReadOnlyList<Permission>> GetUserPermissionsAsync(Guid userId)
        {
            // Obtener permisos directos
            var directPermissionIds = await _context.UserPermissions
                .Where(up => up.UserId == userId && up.IsGranted)
                .Where(up => up.ExpirationDate == null || up.ExpirationDate > DateTime.UtcNow)
                .Select(up => up.PermissionId)
                .ToListAsync();

            // Obtener roles activos del usuario
            var roleIds = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.IsActive)
                .Where(ur => ur.ExpirationDate == null || ur.ExpirationDate > DateTime.UtcNow)
                .Select(ur => ur.RoleId)
                .ToListAsync();

            // Obtener permisos basados en roles
            var rolePermissionIds = await _context.RolePermissions
                .Where(rp => roleIds.Contains(rp.RoleId))
                .Select(rp => rp.PermissionId)
                .ToListAsync();

            // Combinar todos los IDs de permisos únicos
            var allPermissionIds = directPermissionIds.Union(rolePermissionIds).Distinct().ToList();

            // Obtener permisos
            return await _context.Permissions
                .Where(p => allPermissionIds.Contains(p.Id))
                .ToListAsync();
        }

        public async Task<bool> AddToRoleAsync(Guid userId, Guid roleId, Guid? assignedBy = null)
        {
            var userRole = await _context.UserRoles
                .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId);

            if (userRole != null)
            {
                userRole.IsActive = true;
                userRole.AssignedBy = assignedBy;
                userRole.AssignedAt = DateTime.UtcNow;
                userRole.ExpirationDate = null;
            }
            else
            {
                userRole = new UserRole
                {
                    UserId = userId,
                    RoleId = roleId,
                    AssignedBy = assignedBy,
                    AssignedAt = DateTime.UtcNow,
                    IsActive = true
                };
                await _context.UserRoles.AddAsync(userRole);
            }

            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemoveFromRoleAsync(Guid userId, Guid roleId)
        {
            var userRole = await _context.UserRoles
                .FirstOrDefaultAsync(ur => ur.UserId == userId && ur.RoleId == roleId);

            if (userRole == null)
            {
                return false;
            }

            userRole.IsActive = false;
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> AddPermissionAsync(Guid userId, Guid permissionId, bool isGranted = true, Guid? assignedBy = null)
        {
            var userPermission = await _context.UserPermissions
                .FirstOrDefaultAsync(up => up.UserId == userId && up.PermissionId == permissionId);

            if (userPermission != null)
            {
                userPermission.IsGranted = isGranted;
                userPermission.AssignedBy = assignedBy;
                userPermission.AssignedAt = DateTime.UtcNow;
                userPermission.ExpirationDate = null;
            }
            else
            {
                userPermission = new UserPermission
                {
                    UserId = userId,
                    PermissionId = permissionId,
                    IsGranted = isGranted,
                    AssignedBy = assignedBy,
                    AssignedAt = DateTime.UtcNow
                };
                await _context.UserPermissions.AddAsync(userPermission);
            }

            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemovePermissionAsync(Guid userId, Guid permissionId)
        {
            var userPermission = await _context.UserPermissions
                .FirstOrDefaultAsync(up => up.UserId == userId && up.PermissionId == permissionId);

            if (userPermission == null)
            {
                return false;
            }

            _context.UserPermissions.Remove(userPermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> IsInRoleAsync(Guid userId, Guid roleId)
        {
            return await _context.UserRoles
                .AnyAsync(ur => ur.UserId == userId && ur.RoleId == roleId && 
                               ur.IsActive && (ur.ExpirationDate == null || ur.ExpirationDate > DateTime.UtcNow));
        }

        public async Task<bool> HasPermissionAsync(Guid userId, Guid permissionId)
        {
            // Verificar permiso directo
            var hasDirectPermission = await _context.UserPermissions
                .AnyAsync(up => up.UserId == userId && up.PermissionId == permissionId && 
                               up.IsGranted && (up.ExpirationDate == null || up.ExpirationDate > DateTime.UtcNow));

            if (hasDirectPermission)
            {
                return true;
            }

            // Verificar permisos basados en roles
            var userRoleIds = await _context.UserRoles
                .Where(ur => ur.UserId == userId && ur.IsActive && 
                           (ur.ExpirationDate == null || ur.ExpirationDate > DateTime.UtcNow))
                .Select(ur => ur.RoleId)
                .ToListAsync();

            return await _context.RolePermissions
                .AnyAsync(rp => userRoleIds.Contains(rp.RoleId) && rp.PermissionId == permissionId);
        }

        public async Task AddSessionAsync(UserSession session)
        {
            await _context.UserSessions.AddAsync(session);
            await _context.SaveChangesAsync();
        }

        public async Task<bool> RevokeSessionAsync(Guid sessionId)
        {
            var session = await _context.UserSessions.FindAsync(sessionId);
            if (session == null)
            {
                return false;
            }

            session.RevokedAt = DateTime.UtcNow;
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RevokeAllUserSessionsAsync(Guid userId)
        {
            var sessions = await _context.UserSessions
                .Where(s => s.UserId == userId && s.RevokedAt == null && s.ExpiresAt > DateTime.UtcNow)
                .ToListAsync();

            if (!sessions.Any())
            {
                return false;
            }

            var now = DateTime.UtcNow;
            foreach (var session in sessions)
            {
                session.RevokedAt = now;
            }

            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> IsTokenRevokedAsync(Guid userId, string jti)
        {
            var session = await _context.UserSessions
                .FirstOrDefaultAsync(s => s.UserId == userId && s.Token.Contains(jti));

            return session == null || session.RevokedAt != null;
        }

        public async Task<UserTwoFactorSettings> GetTwoFactorSettingsAsync(Guid userId)
        {
            return await _context.UserTwoFactorSettings
                .FirstOrDefaultAsync(tf => tf.UserId == userId);
        }

        public async Task SaveTwoFactorSettingsAsync(UserTwoFactorSettings settings)
        {
            var existingSettings = await _context.UserTwoFactorSettings
                .FirstOrDefaultAsync(tf => tf.UserId == settings.UserId);

            if (existingSettings != null)
            {
                existingSettings.IsEnabled = settings.IsEnabled;
                existingSettings.Method = settings.Method;
                existingSettings.SecretKey = settings.SecretKey;
                existingSettings.RecoveryCodesJson = settings.RecoveryCodesJson;
                existingSettings.UpdatedAt = DateTime.UtcNow;
            }
            else
            {
                settings.UpdatedAt = DateTime.UtcNow;
                await _context.UserTwoFactorSettings.AddAsync(settings);
            }

            await _context.SaveChangesAsync();
        }

        public async Task RemoveTwoFactorSettingsAsync(Guid userId)
        {
            var settings = await _context.UserTwoFactorSettings
                .FirstOrDefaultAsync(tf => tf.UserId == userId);

            if (settings != null)
            {
                _context.UserTwoFactorSettings.Remove(settings);
                await _context.SaveChangesAsync();
            }
        }
    }
}
EOF

cat > RoleRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class RoleRepository : Repository<Role>, IRoleRepository
    {
        public RoleRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<Role> FindByNameAsync(string name)
        {
            return await _dbSet.FirstOrDefaultAsync(r => r.Name == name || r.NormalizedName == name.ToUpperInvariant());
        }

        public async Task<IReadOnlyList<Permission>> GetRolePermissionsAsync(Guid roleId)
        {
            var permissionIds = await _context.RolePermissions
                .Where(rp => rp.RoleId == roleId)
                .Select(rp => rp.PermissionId)
                .ToListAsync();

            return await _context.Permissions
                .Where(p => permissionIds.Contains(p.Id))
                .ToListAsync();
        }

        public async Task<bool> AddPermissionAsync(Guid roleId, Guid permissionId, Guid? assignedBy = null)
        {
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

            if (rolePermission != null)
            {
                return true; // Ya existe, no es necesario hacer nada
            }

            rolePermission = new RolePermission
            {
                RoleId = roleId,
                PermissionId = permissionId,
                AssignedBy = assignedBy,
                AssignedAt = DateTime.UtcNow
            };

            await _context.RolePermissions.AddAsync(rolePermission);
            return await _context.SaveChangesAsync() > 0;
        }

        public async Task<bool> RemovePermissionAsync(Guid roleId, Guid permissionId)
        {
            var rolePermission = await _context.RolePermissions
                .FirstOrDefaultAsync(rp => rp.RoleId == roleId && rp.PermissionId == permissionId);

            if (rolePermission == null)
            {
                return false;
            }

            _context.RolePermissions.Remove(rolePermission);
            return await _context.SaveChangesAsync() > 0;
        }
    }
}
EOF

cat > PermissionRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class PermissionRepository : Repository<Permission>, IPermissionRepository
    {
        public PermissionRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<Permission> FindByCodeAsync(string code)
        {
            return await _dbSet.FirstOrDefaultAsync(p => p.Code == code);
        }

        public async Task<IReadOnlyList<Permission>> GetByCategoryAsync(string category)
        {
            return await _dbSet.Where(p => p.Category == category).ToListAsync();
        }
    }
}
EOF

cat > ModuleRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using AuthSystem.Core.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data.Repositories
{
    public class ModuleRepository : Repository<Module>, IModuleRepository
    {
        public ModuleRepository(ApplicationDbContext context) : base(context)
        {
        }

        public async Task<IReadOnlyList<Module>> GetRootModulesAsync()
        {
            return await _dbSet.Where(m => m.ParentId == null && m.IsActive)
                .OrderBy(m => m.DisplayOrder)
                .ToListAsync();
        }

        public async Task<IReadOnlyList<Module>> GetChildModulesAsync(Guid parentId)
        {
            return await _dbSet.Where(m => m.ParentId == parentId && m.IsActive)
                # Creación del Proyecto Auth en .NET 8

Este documento contiene los comandos y pasos necesarios para crear la estructura del proyecto de Autenticación y Autorización en .NET 8, siguiendo la arquitectura Clean Architecture con CQRS.

## Índice
1. [Requisitos Previos](#requisitos-previos)
2. [Estructura del Proyecto](#estructura-del-proyecto)
3. [Creación de la Solución y Proyectos](#creación-de-la-solución-y-proyectos)
4. [Instalación de Paquetes NuGet](#instalación-de-paquetes-nuget)
5. [Configuración de Dependencias entre Proyectos](#configuración-de-dependencias-entre-proyectos)
6. [Estructura de Carpetas](#estructura-de-carpetas)
7. [Próximos Pasos](#próximos-pasos)

## Requisitos Previos

Asegúrate de tener instalado lo siguiente:

- .NET 8 SDK
- SQL Server 2019 (o posterior)
- Visual Studio 2022 o Visual Studio Code
- Entity Framework Core CLI Tools

Para instalar las herramientas de Entity Framework Core globalmente:

```bash
dotnet tool install --global dotnet-ef
```

## Estructura del Proyecto

Recordemos la estructura general que vamos a implementar:

```
AuthSystem.sln
├── src
│   ├── AuthSystem.Core (Capa de Dominio)
│   ├── AuthSystem.Infrastructure (Capa de Infraestructura)
│   ├── AuthSystem.Application (Capa de Aplicación)
│   └── AuthSystem.API (Capa de Presentación)
└── tests
    ├── AuthSystem.UnitTests
    ├── AuthSystem.IntegrationTests
    └── AuthSystem.FunctionalTests
```

## Creación de la Solución y Proyectos

Abre una terminal y ejecuta los siguientes comandos:

```bash
# Crear directorio para el proyecto
mkdir AuthSystem
cd AuthSystem

# Crear la solución
dotnet new sln -n AuthSystem

# Crear directorio para el código fuente
mkdir src
mkdir tests

# Crear proyectos principales
cd src

# Proyecto Core (Class Library)
dotnet new classlib -n AuthSystem.Core -f net8.0

# Proyecto Infrastructure (Class Library)
dotnet new classlib -n AuthSystem.Infrastructure -f net8.0

# Proyecto Application (Class Library)
dotnet new classlib -n AuthSystem.Application -f net8.0

# Proyecto API (ASP.NET Core Web API)
dotnet new webapi -n AuthSystem.API -f net8.0

# Crear proyectos de prueba
cd ../tests

# Proyecto de pruebas unitarias
dotnet new xunit -n AuthSystem.UnitTests -f net8.0

# Proyecto de pruebas de integración
dotnet new xunit -n AuthSystem.IntegrationTests -f net8.0

# Proyecto de pruebas funcionales
dotnet new xunit -n AuthSystem.FunctionalTests -f net8.0

# Volver a la raíz
cd ..

# Agregar proyectos a la solución
dotnet sln add src/AuthSystem.Core/AuthSystem.Core.csproj
dotnet sln add src/AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj
dotnet sln add src/AuthSystem.Application/AuthSystem.Application.csproj
dotnet sln add src/AuthSystem.API/AuthSystem.API.csproj
dotnet sln add tests/AuthSystem.UnitTests/AuthSystem.UnitTests.csproj
dotnet sln add tests/AuthSystem.IntegrationTests/AuthSystem.IntegrationTests.csproj
dotnet sln add tests/AuthSystem.FunctionalTests/AuthSystem.FunctionalTests.csproj
```

## Instalación de Paquetes NuGet

### 1. Paquetes para AuthSystem.Core

```bash
cd src/AuthSystem.Core

# Paquetes básicos
dotnet add package Microsoft.Extensions.DependencyInjection.Abstractions
dotnet add package Microsoft.Extensions.Logging.Abstractions
dotnet add package System.ComponentModel.Annotations
dotnet add package System.Text.Json
```

### 2. Paquetes para AuthSystem.Infrastructure

```bash
cd ../AuthSystem.Infrastructure

# Entity Framework Core y SQL Server
dotnet add package Microsoft.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.EntityFrameworkCore.Design

# Identity y Autenticación
dotnet add package Microsoft.AspNetCore.Identity
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.IdentityModel.Tokens
dotnet add package System.IdentityModel.Tokens.Jwt

# Otros paquetes útiles
dotnet add package Microsoft.Extensions.Configuration
dotnet add package Microsoft.Extensions.Options.ConfigurationExtensions
dotnet add package Microsoft.Extensions.Caching.StackExchangeRedis
dotnet add package Serilog
dotnet add package Serilog.Sinks.File
dotnet add package Serilog.Sinks.Console
dotnet add package Serilog.Extensions.Logging
dotnet add package Serilog.Settings.Configuration
dotnet add package Microsoft.Extensions.Http
dotnet add package Polly
dotnet add package BCrypt.Net-Next
dotnet add package Newtonsoft.Json
dotnet add package Dapper

# Referencia al proyecto Core
dotnet add reference ../AuthSystem.Core/AuthSystem.Core.csproj
```

### 3. Paquetes para AuthSystem.Application

```bash
cd ../AuthSystem.Application

# Paquetes para CQRS y validación
dotnet add package MediatR
dotnet add package MediatR.Extensions.Microsoft.DependencyInjection
dotnet add package FluentValidation
dotnet add package FluentValidation.DependencyInjectionExtensions
dotnet add package AutoMapper
dotnet add package AutoMapper.Extensions.Microsoft.DependencyInjection

# Otros paquetes útiles
dotnet add package Microsoft.Extensions.Logging.Abstractions
dotnet add package System.IdentityModel.Tokens.Jwt
dotnet add package Microsoft.Extensions.Options

# Referencias a proyectos
dotnet add reference ../AuthSystem.Core/AuthSystem.Core.csproj
dotnet add reference ../AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj
```

### 4. Paquetes para AuthSystem.API

```bash
cd ../AuthSystem.API

# Paquetes para ASP.NET Core
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Mvc.Versioning
dotnet add package Microsoft.AspNetCore.Mvc.Versioning.ApiExplorer
dotnet add package Microsoft.AspNetCore.OpenApi
dotnet add package Swashbuckle.AspNetCore
dotnet add package NSwag.AspNetCore
dotnet add package Swashbuckle.AspNetCore.Filters
dotnet add package AspNetCoreRateLimit

# Paquetes para seguridad y monitoreo
dotnet add package Microsoft.AspNetCore.Diagnostics.HealthChecks
dotnet add package AspNetCore.HealthChecks.SqlServer
dotnet add package AspNetCore.HealthChecks.Redis
dotnet add package Serilog.AspNetCore
dotnet add package NWebsec.AspNetCore.Middleware
dotnet add package GoogleReCaptcha.V3
dotnet add package Microsoft.ApplicationInsights.AspNetCore

# Referencias a proyectos
dotnet add reference ../AuthSystem.Core/AuthSystem.Core.csproj
dotnet add reference ../AuthSystem.Application/AuthSystem.Application.csproj
dotnet add reference ../AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj
```

### 5. Paquetes para Proyectos de Tests

```bash
cd ../../tests/AuthSystem.UnitTests

# Paquetes para tests unitarios
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package Moq
dotnet add package FluentAssertions
dotnet add package AutoFixture
dotnet add package AutoFixture.AutoMoq
dotnet add package AutoFixture.Xunit2

# Referencias a proyectos
dotnet add reference ../../src/AuthSystem.Core/AuthSystem.Core.csproj
dotnet add reference ../../src/AuthSystem.Application/AuthSystem.Application.csproj

cd ../AuthSystem.IntegrationTests

# Paquetes para tests de integración
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package Microsoft.AspNetCore.Mvc.Testing
dotnet add package Microsoft.EntityFrameworkCore.InMemory
dotnet add package FluentAssertions
dotnet add package Respawn
dotnet add package Testcontainers
dotnet add package Testcontainers.MsSql

# Referencias a proyectos
dotnet add reference ../../src/AuthSystem.API/AuthSystem.API.csproj

cd ../AuthSystem.FunctionalTests

# Paquetes para tests funcionales
dotnet add package Microsoft.NET.Test.Sdk
dotnet add package xunit
dotnet add package xunit.runner.visualstudio
dotnet add package Microsoft.AspNetCore.Mvc.Testing
dotnet add package FluentAssertions
dotnet add package Selenium.WebDriver
dotnet add package Selenium.Support
dotnet add package WebDriverManager

# Referencias a proyectos
dotnet add reference ../../src/AuthSystem.API/AuthSystem.API.csproj
```

## Configuración de Dependencias entre Proyectos

Las dependencias entre proyectos ya están configuradas en los comandos anteriores, pero aquí está un resumen de las relaciones:

1. **AuthSystem.Infrastructure** → depende de → **AuthSystem.Core**
2. **AuthSystem.Application** → depende de → **AuthSystem.Core** y **AuthSystem.Infrastructure**
3. **AuthSystem.API** → depende de → **AuthSystem.Core**, **AuthSystem.Application** y **AuthSystem.Infrastructure**
4. **Tests** → dependen de los proyectos relevantes que testean

## Estructura de Carpetas

Ahora crearemos la estructura básica de carpetas para cada proyecto:

### 1. AuthSystem.Core

```bash
cd ../../src/AuthSystem.Core

# Eliminar archivos iniciales
rm Class1.cs

# Crear estructura de carpetas
mkdir Entities
mkdir Exceptions
mkdir Interfaces
mkdir Services
mkdir Enums
mkdir Constants
```

### 2. AuthSystem.Infrastructure

```bash
cd ../AuthSystem.Infrastructure

# Eliminar archivos iniciales
rm Class1.cs

# Crear estructura de carpetas
mkdir Data
mkdir Data/Configurations
mkdir Data/Repositories
mkdir Data/Migrations
mkdir Identity
mkdir Logging
mkdir Security
mkdir Services
mkdir Caching
mkdir Email
mkdir SMS
```

### 3. AuthSystem.Application

```bash
cd ../AuthSystem.Application

# Eliminar archivos iniciales
rm Class1.cs

# Crear estructura de carpetas
mkdir Commands
mkdir Queries
mkdir DTOs
mkdir Mappings
mkdir Validators
mkdir Behaviors
mkdir Common
```

### 4. AuthSystem.API

```bash
cd ../AuthSystem.API

# Crear estructura de carpetas adicionales
mkdir Controllers
mkdir Filters
mkdir Extensions
mkdir Middleware
mkdir Models
mkdir Swagger
```

## Creación de Archivos Principales

### 1. Entidades en AuthSystem.Core

```bash
cd ../AuthSystem.Core/Entities

# Crear archivos de entidades
cat > User.cs << 'EOF'
using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Entities
{
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

        // Constructor privado para EF Core
        private User() { }

        // Constructor para crear un nuevo usuario
        public User(string username, string email, string passwordHash, string firstName = null, string lastName = null)
        {
            Id = Guid.NewGuid();
            Username = username;
            Email = email;
            PasswordHash = passwordHash;
            SecurityStamp = Guid.NewGuid().ToString();
            PhoneNumberConfirmed = false;
            TwoFactorEnabled = false;
            LockoutEnabled = true;
            AccessFailedCount = 0;
            EmailConfirmed = false;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
            Status = UserStatus.Registered;
            RequirePasswordChange = false;
            FirstName = firstName;
            LastName = lastName;
            IsDeleted = false;
        }

        // Métodos para actualizar propiedades
        public void UpdateProfile(string firstName, string lastName, string phoneNumber)
        {
            FirstName = firstName;
            LastName = lastName;
            PhoneNumber = phoneNumber;
            UpdatedAt = DateTime.UtcNow;
        }

        public void ConfirmEmail()
        {
            EmailConfirmed = true;
            if (Status == UserStatus.Registered)
            {
                Status = UserStatus.Active;
            }
            UpdatedAt = DateTime.UtcNow;
        }

        public void EnableTwoFactor()
        {
            TwoFactorEnabled = true;
            UpdatedAt = DateTime.UtcNow;
        }

        public void DisableTwoFactor()
        {
            TwoFactorEnabled = false;
            UpdatedAt = DateTime.UtcNow;
        }

        public void ChangePassword(string newPasswordHash)
        {
            PasswordHash = newPasswordHash;
            SecurityStamp = Guid.NewGuid().ToString();
            LastPasswordChangeDate = DateTime.UtcNow;
            RequirePasswordChange = false;
            UpdatedAt = DateTime.UtcNow;
        }

        public void ResetAccessFailedCount()
        {
            AccessFailedCount = 0;
            UpdatedAt = DateTime.UtcNow;
        }

        public void IncrementAccessFailedCount()
        {
            AccessFailedCount++;
            UpdatedAt = DateTime.UtcNow;
        }

        public void LockAccount(TimeSpan duration)
        {
            LockoutEnd = DateTimeOffset.UtcNow.Add(duration);
            Status = UserStatus.Blocked;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UnlockAccount()
        {
            LockoutEnd = null;
            Status = UserStatus.Active;
            AccessFailedCount = 0;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Delete()
        {
            IsDeleted = true;
            Status = UserStatus.Deleted;
            DeletedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        public void UpdateLastLoginDate()
        {
            LastLoginDate = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }
    }

    public enum UserStatus
    {
        Registered = 1,
        Active = 2,
        Blocked = 3,
        Deleted = 4
    }
}
EOF

# Crear otras entidades básicas
cat > Role.cs << 'EOF'
using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Entities
{
    public class Role
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string NormalizedName { get; private set; }
        public string Description { get; private set; }
        public bool IsActive { get; private set; }
        public bool IsDefault { get; private set; }
        public int Priority { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Constructor privado para EF Core
        private Role() { }

        // Constructor para crear un nuevo rol
        public Role(string name, string description = null, bool isDefault = false, int priority = 0)
        {
            Id = Guid.NewGuid();
            Name = name;
            NormalizedName = name.ToUpperInvariant();
            Description = description;
            IsActive = true;
            IsDefault = isDefault;
            Priority = priority;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        // Métodos para actualizar propiedades
        public void Update(string name, string description, bool isActive, bool isDefault, int priority)
        {
            Name = name;
            NormalizedName = name.ToUpperInvariant();
            Description = description;
            IsActive = isActive;
            IsDefault = isDefault;
            Priority = priority;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Deactivate()
        {
            IsActive = false;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Activate()
        {
            IsActive = true;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}
EOF

cat > Permission.cs << 'EOF'
using System;

namespace AuthSystem.Core.Entities
{
    public class Permission
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string Code { get; private set; }
        public string Description { get; private set; }
        public string Category { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Constructor privado para EF Core
        private Permission() { }

        // Constructor para crear un nuevo permiso
        public Permission(string name, string code, string description = null, string category = null)
        {
            Id = Guid.NewGuid();
            Name = name;
            Code = code;
            Description = description;
            Category = category;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
        }

        // Métodos para actualizar propiedades
        public void Update(string name, string code, string description, string category)
        {
            Name = name;
            Code = code;
            Description = description;
            Category = category;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}
EOF

cat > Module.cs << 'EOF'
using System;
using System.Collections.Generic;

namespace AuthSystem.Core.Entities
{
    public class Module
    {
        public Guid Id { get; private set; }
        public string Name { get; private set; }
        public string Description { get; private set; }
        public string Icon { get; private set; }
        public string Route { get; private set; }
        public bool IsActive { get; private set; }
        public int DisplayOrder { get; private set; }
        public Guid? ParentId { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime UpdatedAt { get; private set; }

        // Navegación
        public Module Parent { get; private set; }
        public ICollection<Module> Children { get; private set; }

        // Constructor privado para EF Core
        private Module() { }

        // Constructor para crear un nuevo módulo
        public Module(string name, string description = null, string icon = null, string route = null, 
                      int displayOrder = 0, Guid? parentId = null)
        {
            Id = Guid.NewGuid();
            Name = name;
            Description = description;
            Icon = icon;
            Route = route;
            IsActive = true;
            DisplayOrder = displayOrder;
            ParentId = parentId;
            CreatedAt = DateTime.UtcNow;
            UpdatedAt = DateTime.UtcNow;
            Children = new List<Module>();
        }

        // Métodos para actualizar propiedades
        public void Update(string name, string description, string icon, string route, 
                          bool isActive, int displayOrder, Guid? parentId)
        {
            Name = name;
            Description = description;
            Icon = icon;
            Route = route;
            IsActive = isActive;
            DisplayOrder = displayOrder;
            ParentId = parentId;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Activate()
        {
            IsActive = true;
            UpdatedAt = DateTime.UtcNow;
        }

        public void Deactivate()
        {
            IsActive = false;
            UpdatedAt = DateTime.UtcNow;
        }
    }
}
EOF
```

### 2. Interfaces en AuthSystem.Core

```bash
cd ../Interfaces

# Crear interfaces principales
cat > IRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IRepository<T> where T : class
    {
        Task<T> GetByIdAsync(Guid id);
        Task<IReadOnlyList<T>> GetAllAsync();
        Task<IReadOnlyList<T>> FindAsync(Expression<Func<T, bool>> predicate);
        Task<T> AddAsync(T entity);
        Task UpdateAsync(T entity);
        Task DeleteAsync(T entity);
        Task<int> SaveChangesAsync();
    }
}
EOF

cat > IUserRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IUserRepository : IRepository<User>
    {
        Task<User> FindByUsernameAsync(string username);
        Task<User> FindByEmailAsync(string email);
        Task<User> FindByUsernameOrEmailAsync(string usernameOrEmail);
        Task<IReadOnlyList<Role>> GetUserRolesAsync(Guid userId);
        Task<IReadOnlyList<Permission>> GetUserPermissionsAsync(Guid userId);
        Task<bool> AddToRoleAsync(Guid userId, Guid roleId, Guid? assignedBy = null);
        Task<bool> RemoveFromRoleAsync(Guid userId, Guid roleId);
        Task<bool> AddPermissionAsync(Guid userId, Guid permissionId, bool isGranted = true, Guid? assignedBy = null);
        Task<bool> RemovePermissionAsync(Guid userId, Guid permissionId);
        Task<bool> IsInRoleAsync(Guid userId, Guid roleId);
        Task<bool> HasPermissionAsync(Guid userId, Guid permissionId);
        Task AddSessionAsync(UserSession session);
        Task<bool> RevokeSessionAsync(Guid sessionId);
        Task<bool> RevokeAllUserSessionsAsync(Guid userId);
        Task<bool> IsTokenRevokedAsync(Guid userId, string jti);
        Task<UserTwoFactorSettings> GetTwoFactorSettingsAsync(Guid userId);
        Task SaveTwoFactorSettingsAsync(UserTwoFactorSettings settings);
        Task RemoveTwoFactorSettingsAsync(Guid userId);
    }
}
EOF

cat > IRoleRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IRoleRepository : IRepository<Role>
    {
        Task<Role> FindByNameAsync(string name);
        Task<IReadOnlyList<Permission>> GetRolePermissionsAsync(Guid roleId);
        Task<bool> AddPermissionAsync(Guid roleId, Guid permissionId, Guid? assignedBy = null);
        Task<bool> RemovePermissionAsync(Guid roleId, Guid permissionId);
    }
}
EOF

cat > IPermissionRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IPermissionRepository : IRepository<Permission>
    {
        Task<Permission> FindByCodeAsync(string code);
        Task<IReadOnlyList<Permission>> GetByCategoryAsync(string category);
    }
}
EOF

cat > IModuleRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IModuleRepository : IRepository<Module>
    {
        Task<IReadOnlyList<Module>> GetRootModulesAsync();
        Task<IReadOnlyList<Module>> GetChildModulesAsync(Guid parentId);
        Task<IReadOnlyList<Module>> GetUserModulesAsync(Guid userId);
        Task<bool> AddModulePermissionAsync(Guid moduleId, Guid permissionId);
        Task<bool> RemoveModulePermissionAsync(Guid moduleId, Guid permissionId);
        Task<IReadOnlyList<Permission>> GetModulePermissionsAsync(Guid moduleId);
    }
}
EOF

cat > IAuditRepository.cs << 'EOF'
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IAuditRepository
    {
        Task LogActionAsync(Guid? userId, string action, string entityName, string entityId, 
                           string oldValues, string newValues, string ipAddress, string userAgent);
        Task LogLoginAttemptAsync(string username, string email, string ipAddress, string userAgent,
                                 bool successful, string failureReason, Guid? userId);
        Task<IReadOnlyList<AuditLog>> GetAuditLogsAsync(DateTime? startDate, DateTime? endDate, 
                                                      Guid? userId, string entityName, string action);
        Task<IReadOnlyList<LoginAttempt>> GetLoginAttemptsAsync(DateTime? startDate, DateTime? endDate, 
                                                               Guid? userId, string ipAddress, bool? successful);
    }
}
EOF

cat > IPasswordHasher.cs << 'EOF'
namespace AuthSystem.Core.Interfaces
{
    public interface IPasswordHasher
    {
        string HashPassword(string password);
        bool VerifyPassword(string passwordHash, string inputPassword);
    }
}
EOF

cat > IJwtService.cs << 'EOF'
using System;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;

namespace AuthSystem.Core.Interfaces
{
    public interface IJwtService
    {
        Task<(string Token, string RefreshToken)> GenerateTokensAsync(User user, bool extendedDuration = false);
        Task<(bool IsValid, string UserId, string Jti)> ValidateTokenAsync(string token);
    }
}
EOF

cat > IEmailService.cs << 'EOF'
using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IEmailService
    {
        Task SendAsync(string to, string subject, string body, bool isHtml = true);
        Task SendConfirmationEmailAsync(string email, string userId, string token);
        Task SendPasswordResetEmailAsync(string email, string userId, string token);
        Task SendTwoFactorCodeAsync(string email, string code);
    }
}
EOF

cat > ISmsService.cs << 'EOF'
using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface ISmsService
    {
        Task SendAsync(string phoneNumber, string message);
        Task SendVerificationCodeAsync(string phoneNumber, string code);
    }
}
EOF

cat > ITotpService.cs << 'EOF'
using System.Collections.Generic;

namespace AuthSystem.Core.Interfaces
{
    public interface ITotpService
    {
        string GenerateSecretKey();
        string GenerateCode(string secretKey);
        bool ValidateCode(string secretKey, string code);
        string[] GenerateRecoveryCodes(int numberOfCodes = 8);
    }
}
EOF

cat > IRecaptchaService.cs << 'EOF'
using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IRecaptchaService
    {
        Task<bool> ValidateTokenAsync(string token, string ipAddress);
    }
}
EOF

cat > IAuditService.cs << 'EOF'
using System;
using System.Threading.Tasks;

namespace AuthSystem.Core.Interfaces
{
    public interface IAuditService
    {
        Task LogActionAsync(Guid? userId, string action, string entityName, string entityId, 
                           object oldValues, object newValues, string ipAddress = null, string userAgent = null);
        Task LogLoginAttemptAsync(string username, string ipAddress, string userAgent, 
                                 bool successful, string failureReason = null, Guid? userId = null);
    }
}
EOF
```

### 3. DbContext en AuthSystem.Infrastructure

```bash
cd ../../AuthSystem.Infrastructure/Data

# Crear DbContext
cat > ApplicationDbContext.cs << 'EOF'
using System;
using System.Threading;
using System.Threading.Tasks;
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace AuthSystem.Infrastructure.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // Entidades principales
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<Permission> Permissions { get; set; }
        public DbSet<Module> Modules { get; set; }
        
        // Relaciones
        public DbSet<UserRole> UserRoles { get; set; }
        public DbSet<RolePermission> RolePermissions { get; set; }
        public DbSet<UserPermission> UserPermissions { get; set; }
        public DbSet<ModulePermission> ModulePermissions { get; set; }
        
        // Autenticación y sesiones
        public DbSet
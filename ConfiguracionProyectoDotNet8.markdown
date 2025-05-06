# Configuración del Proyecto de Sistema de Autenticación en .NET 8

Este documento proporciona los comandos paso a paso para crear una solución en .NET 8 con la estructura descrita en la arquitectura del sistema de autenticación, incluyendo todas las librerías NuGet necesarias para soportar las funcionalidades descritas.

## Requisitos Previos
- **.NET 8 SDK** instalado (verifica con `dotnet --version` que retorne 8.0.x).
- **Visual Studio Code** o **Visual Studio 2022** (opcional, para edición).
- Una terminal o línea de comandos.
- SQL Server 2019 o una base de datos compatible (para Entity Framework Core).
- Redis instalado (para almacenamiento en caché de sesiones).

## Estructura de la Solución
La solución sigue la arquitectura limpia (Clean Architecture) con CQRS e incluye los siguientes proyectos:
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

## Funcionalidades y Librerías Requeridas
Basado en la arquitectura, el proyecto necesita soporte para:
- **Arquitectura Limpia y CQRS**: MediatR para manejar comandos y consultas.
- **Autenticación y Autorización**: ASP.NET Core Identity, JWT para autenticación basada en tokens.
- **Base de Datos**: Entity Framework Core con SQL Server para persistencia de datos.
- **Caché**: StackExchange.Redis para gestión de sesiones.
- **Registro (Logging)**: Serilog para registros estructurados.
- **Monitoreo**: Application Insights o Prometheus (configuración opcional).
- **Seguridad**: Hash de contraseñas, autenticación multifactor (MFA), validación reCAPTCHA.
- **Auditoría**: Auditoría personalizada con interceptores de EF Core.
- **API**: API Web de ASP.NET Core con Swagger para documentación.
- **Pruebas**: xUnit, Moq y FluentAssertions para pruebas unitarias e integración.

A continuación, se presentan los comandos para crear la solución e instalar todas las librerías necesarias.

## Comandos Paso a Paso

### 1. Crear la Solución y Estructura de Directorios
```bash
# Crear el directorio raíz
mkdir AuthSystem
cd AuthSystem

# Crear la solución
dotnet new sln -n AuthSystem

# Crear directorios src y tests
mkdir src
mkdir tests

# Crear proyectos bajo src
cd src
dotnet new classlib -n AuthSystem.Core
dotnet new classlib -n AuthSystem.Infrastructure
dotnet new classlib -n AuthSystem.Application
dotnet new webapi -n AuthSystem.API
cd ..

# Crear proyectos de pruebas bajo tests
cd tests
dotnet new xunit -n AuthSystem.UnitTests
dotnet new xunit -n AuthSystem.IntegrationTests
dotnet new xunit -n AuthSystem.FunctionalTests
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

### 2. Configurar Referencias entre Proyectos
```bash
# AuthSystem.Infrastructure referencia a AuthSystem.Core
dotnet add src/AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj reference src/AuthSystem.Core/AuthSystem.Core.csproj

# AuthSystem.Application referencia a AuthSystem.Core
dotnet add src/AuthSystem.Application/AuthSystem.Application.csproj reference src/AuthSystem.Core/AuthSystem.Core.csproj

# AuthSystem.API referencia a AuthSystem.Infrastructure y AuthSystem.Application
dotnet add src/AuthSystem.API/AuthSystem.API.csproj reference src/AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj
dotnet add src/AuthSystem.API/AuthSystem.API.csproj reference src/AuthSystem.Application/AuthSystem.Application.csproj

# Proyectos de pruebas referencian todos los proyectos de src
dotnet add tests/AuthSystem.UnitTests/AuthSystem.UnitTests.csproj reference src/AuthSystem.Core/AuthSystem.Core.csproj
dotnet add tests/AuthSystem.UnitTests/AuthSystem.UnitTests.csproj reference src/AuthSystem.Application/AuthSystem.Application.csproj
dotnet add tests/AuthSystem.IntegrationTests/AuthSystem.IntegrationTests.csproj reference src/AuthSystem.Core/AuthSystem.Core.csproj
dotnet add tests/AuthSystem.IntegrationTests/AuthSystem.IntegrationTests.csproj reference src/AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj
dotnet add tests/AuthSystem.IntegrationTests/AuthSystem.IntegrationTests.csproj reference src/AuthSystem.Application/AuthSystem.Application.csproj
dotnet add tests/AuthSystem.FunctionalTests/AuthSystem.FunctionalTests.csproj reference src/AuthSystem.Core/AuthSystem.Core.csproj
dotnet add tests/AuthSystem.FunctionalTests/AuthSystem.FunctionalTests.csproj reference src/AuthSystem.Infrastructure/AuthSystem.Infrastructure.csproj
dotnet add tests/AuthSystem.FunctionalTests/AuthSystem.FunctionalTests.csproj reference src/AuthSystem.Application/AuthSystem.Application.csproj
```

### 3. Instalar Paquetes NuGet
Los siguientes paquetes son necesarios para cada proyecto según las funcionalidades descritas.

#### AuthSystem.Core
Este proyecto contiene entidades, interfaces y lógica de dominio.
```bash
cd src/AuthSystem.Core
dotnet add package MediatR --version 12.4.1
dotnet add package FluentValidation --version 11.10.0
cd ../..
```

#### AuthSystem.Infrastructure
Este proyecto maneja el acceso a datos (EF Core), identidad, caché y seguridad.
```bash
cd src/AuthSystem.Infrastructure
dotnet add package Microsoft.EntityFrameworkCore --version 8.0.10
dotnet add package Microsoft.EntityFrameworkCore.SqlServer --version 8.0.10
dotnet add package Microsoft.EntityFrameworkCore.Design --version 8.0.10
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore --version 8.0.10
dotnet add package StackExchange.Redis --version 2.8.16
dotnet add package Serilog.AspNetCore --version 8.0.3
dotnet add package Microsoft.Extensions.DependencyInjection.Abstractions --version 8.0.2
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 8.0.10
dotnet add package System.IdentityModel.Tokens.Jwt --version 8.1.2
dotnet add package Microsoft.ApplicationInsights.AspNetCore --version 2.22.0
dotnet add package Twilio --version 7.3.1
cd ../..
```

#### AuthSystem.Application
Este proyecto contiene comandos, consultas, DTOs y validadores.
```bash
cd src/AuthSystem.Application
dotnet add package MediatR --version 12.4.1
dotnet add package FluentValidation --version 11.10.0
dotnet add package AutoMapper --version 13.0.1
dotnet add package AutoMapper.Extensions.Microsoft.DependencyInjection --version 12.0.1
cd ../..
```

#### AuthSystem.API
Este proyecto es la capa de presentación (API Web).
```bash
cd src/AuthSystem.API
dotnet add package Microsoft.EntityFrameworkCore.Design --version 8.0.10
dotnet add package Swashbuckle.AspNetCore --version 6.9.0
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 8.0.10
dotnet add package Serilog.AspNetCore --version 8.0.3
dotnet add package Microsoft.ApplicationInsights.AspNetCore --version 2.22.0
cd ../..
```

#### Proyectos de Pruebas
Los proyectos de pruebas requieren frameworks de pruebas y librerías de mocking.
```bash
# Pruebas Unitarias
cd tests/AuthSystem.UnitTests
dotnet add package xunit --version 2.9.2
dotnet add package Moq --version 4.20.70
dotnet add package FluentAssertions --version 6.12.1
cd ../..

# Pruebas de Integración
cd tests/AuthSystem.IntegrationTests
dotnet add package xunit --version 2.9.2
dotnet add package Moq --version 4.20.70
dotnet add package FluentAssertions --version 6.12.1
dotnet add package Microsoft.AspNetCore.Mvc.Testing --version 8.0.10
dotnet add package Microsoft.EntityFrameworkCore.InMemory --version 8.0.10
cd ../..

# Pruebas Funcionales
cd tests/AuthSystem.FunctionalTests
dotnet add package xunit --version 2.9.2
dotnet add package Moq --version 4.20.70
dotnet add package FluentAssertions --version 6.12.1
dotnet add package Microsoft.AspNetCore.Mvc.Testing --version 8.0.10
cd ../..
```

### 4. Verificar Instalación de Paquetes
Asegúrate de que todos los paquetes se instalen correctamente restaurando la solución:
```bash
dotnet restore
```

### 5. Crear Estructura de Carpetas Inicial
Crea la estructura de carpetas dentro de cada proyecto según la arquitectura descrita.

#### AuthSystem.Core
```bash
cd src/AuthSystem.Core
mkdir Entities
mkdir Exceptions
mkdir Interfaces
mkdir Services
cd ../..
```

#### AuthSystem.Infrastructure
```bash
cd src/AuthSystem.Infrastructure
mkdir Data
mkdir Data/Configurations
mkdir Data/Repositories
mkdir Identity
mkdir Logging
mkdir Security
cd ../..
```

#### AuthSystem.Application
```bash
cd src/AuthSystem.Application
mkdir Commands
mkdir Queries
mkdir DTOs
mkdir Mappings
mkdir Validators
cd ../..
```

#### AuthSystem.API
```bash
cd src/AuthSystem.API
mkdir Controllers
mkdir Filters
mkdir Extensions
mkdir Middleware
cd ../..
```

### 6. Configurar Program.cs en AuthSystem.API
Actualiza `Program.cs` para incluir los servicios necesarios (EF Core, Identity, JWT, Redis, Serilog, etc.). A continuación, se muestra una configuración de ejemplo:

```bash
cd src/AuthSystem.API
# Crear o actualizar Program.cs
cat > Program.cs << EOL
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Text;
using AuthSystem.Infrastructure.Data; // Ajustar el espacio de nombres según sea necesario
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Configurar Serilog
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .CreateLogger();
builder.Host.UseSerilog();

// Agregar servicios al contenedor
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "AuthSystem API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Por favor ingrese el JWT con Bearer en el campo",
        Name = "Authorization",
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
            new string[] {}
        }
    });
});

// Configurar DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configurar Identity
builder.Services.AddIdentityCore<IdentityUser>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>();

// Configurar autenticación JWT
var jwtSettings = builder.Configuration.GetSection("Jwt");
var key = Encoding.UTF8.GetBytes(jwtSettings["Secret"]);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

// Configurar Redis
builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration.GetConnectionString("Redis");
    options.InstanceName = "AuthSystem_";
});

// Configurar Application Insights
builder.Services.AddApplicationInsightsTelemetry();

// Agregar MediatR
builder.Services.AddMediatR(cfg => cfg.RegisterServicesFromAssemblies(typeof(Program).Assembly));

// Agregar AutoMapper
builder.Services.AddAutoMapper(typeof(Program));

// Configurar CORS (si es necesario)
builder.Services.AddCors(options =>
{
    options.AddPolicy("PermitirTodo", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});

var app = builder.Build();

// Configurar el pipeline de solicitudes HTTP
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseSerilogRequestLogging();
app.UseHttpsRedirection();
app.UseCors("PermitirTodo");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
EOL
cd ../..
```

### 7. Configurar appsettings.json
Agrega la configuración necesaria para JWT, base de datos, Redis y registros.

```bash
cd src/AuthSystem.API
cat > appsettings.json << EOL
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=AuthSystem;Trusted_Connection=True;MultipleActiveResultSets=true",
    "Redis": "localhost:6379"
  },
  "Jwt": {
    "Secret": "TuClaveSecretaMuySeguraAqui1234567890",
    "Issuer": "AuthSystem",
    "Audience": "AuthSystemAPI",
    "ExpirationMinutes": 120,
    "ExtendedExpirationMinutes": 4320
  },
  "Serilog": {
    "Using": [ "Serilog.Sinks.Console", "Serilog.Sinks.File" ],
    "MinimumLevel": {
      "Default": "Information",
      "Override": {
        "Microsoft": "Warning",
        "System": "Warning"
      }
    },
    "WriteTo": [
      { "Name": "Console" },
      {
        "Name": "File",
        "Args": {
          "path": "Logs/log-.txt",
          "rollingInterval": "Day"
        }
      }
    ]
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
EOL
cd ../..
```

### 8. Compilar y Verificar
Compila la solución para asegurarte de que todo está configurado correctamente:
```bash
dotnet build
```

### 9. Notas Adicionales
- **Migraciones de Entity Framework**: Después de implementar el `ApplicationDbContext` en `AuthSystem.Infrastructure`, ejecuta lo siguiente para crear las migraciones iniciales:
  ```bash
  cd src/AuthSystem.API
  dotnet ef migrations add InitialCreate -c ApplicationDbContext -o ../AuthSystem.Infrastructure/Data/Migrations
  dotnet ef database update
  cd ../..
  ```
- **Configuración de Redis**: Asegúrate de que Redis esté ejecutándose localmente o actualiza la cadena de conexión en `appsettings.json`.
- **reCAPTCHA**: Para la validación de reCAPTCHA, agrega el paquete NuGet de Google si es necesario (por ejemplo, `Google.Cloud.RecaptchaEnterprise.V1`) y configura las claves de API en `appsettings.json`.
- **Servicio de SMS**: Para MFA vía SMS, se integró Twilio con el paquete `Twilio` ya incluido en `AuthSystem.Infrastructure`.

### 10. Opcional: Agregar Prometheus y Grafana
Si deseas usar Prometheus para monitoreo, agrega el siguiente paquete a `AuthSystem.API`:
```bash
cd src/AuthSystem.API
dotnet add package prometheus-net.AspNetCore --version 8.2.1
cd ../..
```

Actualiza `Program.cs` para incluir métricas de Prometheus:
```csharp
app.UseMetricServer();
app.UseHttpMetrics();
```

## Resumen de Paquetes Instalados
- **AuthSystem.Core**:
  - MediatR
  - FluentValidation
- **AuthSystem.Infrastructure**:
  - Microsoft.EntityFrameworkCore
  - Microsoft.EntityFrameworkCore.SqlServer
  - Microsoft.EntityFrameworkCore.Design
  - Microsoft.AspNetCore.Identity.EntityFrameworkCore
  - StackExchange.Redis
  - Serilog.AspNetCore
  - Microsoft.Extensions.DependencyInjection.Abstractions
  - Microsoft.AspNetCore.Authentication.JwtBearer
  - System.IdentityModel.Tokens.Jwt
  - Microsoft.ApplicationInsights.AspNetCore
  - Twilio
- **AuthSystem.Application**:
  - MediatR
  - FluentValidation
  - AutoMapper
  - AutoMapper.Extensions.Microsoft.DependencyInjection
- **AuthSystem.API**:
  - Microsoft.EntityFrameworkCore.Design
  - Swashbuckle.AspNetCore
  - Microsoft.AspNetCore.Authentication.JwtBearer
  - Serilog.AspNetCore
  - Microsoft.ApplicationInsights.AspNetCore
  - prometheus-net.AspNetCore (opcional)
- **Proyectos de Pruebas**:
  - xunit
  - Moq
  - FluentAssertions
  - Microsoft.AspNetCore.Mvc.Testing
  - Microsoft.EntityFrameworkCore.InMemory

## Próximos Pasos
- Implementa el contexto de base de datos y las entidades en `AuthSystem.Infrastructure/Data`.
- Copia los scripts SQL del documento de arquitectura para crear el esquema de la base de datos.
- Implementa la lógica de autenticación, el servicio JWT y MFA según lo descrito en la arquitectura.
- Configura pipelines de CI/CD usando GitHub Actions u otra herramienta de CI.
- Configura el monitoreo con Application Insights o Prometheus/Grafana.

Esta configuración asegura que todas las dependencias necesarias estén instaladas y que la estructura del proyecto esté alineada con la arquitectura proporcionada, lista para implementar el sistema de autenticación.
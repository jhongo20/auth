using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// DependencyInjection.cs
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

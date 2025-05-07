using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using System;
using System.IO;
using Microsoft.Extensions.Configuration.Json; // Asegúrate de que tienes esta referencia
//using Microsoft.Extensions.Configuration.FileExtensions; // Añade esta línea

namespace AuthSystem.Infrastructure.Data
{
    public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            // Construir el path al archivo appsettings.json
            var basePath = Directory.GetCurrentDirectory();
            
            // Leer configuración desde appsettings.json
            var configuration = new ConfigurationBuilder()
                .SetBasePath(basePath)
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.Development.json", optional: true)
                .Build();

            var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
            
            // Obtener la cadena de conexión desde la configuración
            var connectionString = configuration.GetConnectionString("DefaultConnection");
            
            // Configurar el contexto para usar SQL Server
            builder.UseSqlServer(connectionString, b => 
                b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName));

            return new ApplicationDbContext(builder.Options);
        }
    }
}
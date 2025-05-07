using System;
using AutoMapper;
using Microsoft.Extensions.DependencyInjection;

namespace AuthSystem.Application.Mappings
{
    public static class AutoMapperConfig
    {
        public static IServiceCollection AddAutoMapperConfiguration(this IServiceCollection services)
        {
            services.AddAutoMapper(cfg =>
            {
                cfg.AddProfile<MappingProfile>();
                // Aquí puedes agregar más perfiles si es necesario
            }, typeof(MappingProfile).Assembly);

            return services;
        }
    }
}
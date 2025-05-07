using AutoMapper;
using AuthSystem.Application.DTOs;
using AuthSystem.Core.Entities;
using System.Linq;
using System;
using System.Collections.Generic;
using System.Text.Json;
using AuthSystem.Application.Commands.Authentication;
using AuthSystem.Application.Commands.User;

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
            CreateMap<Role, RoleDto>()
                .ForMember(dest => dest.Permissions, opt => opt.Ignore());

            // Permission mappings
            CreateMap<Permission, PermissionDto>();

            // Module mappings
            CreateMap<Module, ModuleDto>()
                .ForMember(dest => dest.ParentName, opt => opt.MapFrom(src => src.Parent != null ? src.Parent.Name : null))
                .ForMember(dest => dest.Children, opt => opt.Ignore())
                .ForMember(dest => dest.Permissions, opt => opt.Ignore());

            // UserSession mappings
            CreateMap<UserSession, UserSessionDto>()
                .ForMember(dest => dest.IsCurrentSession, opt => opt.Ignore());

            // AuditLog mappings
            CreateMap<AuditLog, AuditLogDto>()
                .ForMember(dest => dest.Username, opt => opt.Ignore())
                .ForMember(dest => dest.Details, opt => opt.MapFrom(src =>
                    DeserializeJsonOrDefault(src.NewValues)));

            // Request/Response DTOs
            CreateMap<LoginRequestDto, AuthenticateCommand>()
                .ForMember(dest => dest.IpAddress, opt => opt.Ignore())
                .ForMember(dest => dest.UserAgent, opt => opt.Ignore());

            CreateMap<RegisterRequestDto, RegisterCommand>()
                .ForMember(dest => dest.IpAddress, opt => opt.Ignore())
                .ForMember(dest => dest.UserAgent, opt => opt.Ignore());

            CreateMap<TwoFactorRequestDto, TwoFactorLoginCommand>()
                .ForMember(dest => dest.IpAddress, opt => opt.Ignore())
                .ForMember(dest => dest.UserAgent, opt => opt.Ignore());

            CreateMap<ChangePasswordRequestDto, ChangePasswordCommand>()
                .ForMember(dest => dest.UserId, opt => opt.Ignore())
                .ForMember(dest => dest.IpAddress, opt => opt.Ignore())
                .ForMember(dest => dest.UserAgent, opt => opt.Ignore());

            CreateMap<UserProfileDto, UpdateProfileCommand>()
                .ForMember(dest => dest.UserId, opt => opt.Ignore());

            // Otros mapeos bidireccionales
            CreateMap<RoleDto, Role>()
                .ForMember(dest => dest.NormalizedName, opt => opt.MapFrom(src => src.Name.ToUpperInvariant()))
                .ForMember(dest => dest.CreatedAt, opt => opt.Ignore())
                .ForMember(dest => dest.UpdatedAt, opt => opt.Ignore());

            CreateMap<PermissionDto, Permission>()
                .ForMember(dest => dest.CreatedAt, opt => opt.Ignore())
                .ForMember(dest => dest.UpdatedAt, opt => opt.Ignore());

            CreateMap<ModuleDto, Module>()
                .ForMember(dest => dest.CreatedAt, opt => opt.Ignore())
                .ForMember(dest => dest.UpdatedAt, opt => opt.Ignore())
                .ForMember(dest => dest.Parent, opt => opt.Ignore())
                .ForMember(dest => dest.Children, opt => opt.Ignore());

            // Mapeo para listas paginadas
            CreateMap(typeof(List<>), typeof(PaginatedListDto<>))
                .ConvertUsing(typeof(PaginatedListConverter<,>));
        }

        // Método auxiliar para deserializar JSON de manera segura
        private object DeserializeJsonOrDefault(string json)
        {
            if (string.IsNullOrEmpty(json))
                return null;

            try
            {
                return JsonSerializer.Deserialize<object>(json);
            }
            catch
            {
                return null;
            }
        }
    }

    // Converter para mapear listas paginadas
    public class PaginatedListConverter<TSource, TDestination> : ITypeConverter<List<TSource>, PaginatedListDto<TDestination>>
    {
        public PaginatedListDto<TDestination> Convert(List<TSource> source, PaginatedListDto<TDestination> destination, ResolutionContext context)
        {
            if (source == null)
                return null;

            var items = context.Mapper.Map<List<TDestination>>(source);

            return new PaginatedListDto<TDestination>
            {
                Items = items,
                PageIndex = 1,
                PageSize = items.Count,
                TotalCount = items.Count,
                TotalPages = 1
            };
        }
    }
}
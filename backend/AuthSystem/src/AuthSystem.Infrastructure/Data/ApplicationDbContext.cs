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
        public DbSet<UserSession> UserSessions { get; set; }
        public DbSet<UserTwoFactorSettings> UserTwoFactorSettings { get; set; }
        public DbSet<PasswordHistory> PasswordHistory { get; set; }

        // Auditoría
        public DbSet<LoginAttempt> LoginAttempts { get; set; }
        public DbSet<AuditLog> AuditLog { get; set; }

        // Confirmación de correo electrónico
        public DbSet<EmailConfirmationToken> EmailConfirmationTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Aplicar configuraciones de entidades
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

            // Configurar EmailConfirmationToken
            modelBuilder.Entity<EmailConfirmationToken>(entity =>
            {
                entity.ToTable("EmailConfirmationTokens");
                entity.HasKey(e => e.Id);

                entity.Property(e => e.Token)
                      .IsRequired();

                entity.Property(e => e.CreatedAt)
                      .IsRequired();

                entity.Property(e => e.ExpiresAt)
                      .IsRequired();

                entity.HasOne(e => e.User)
                      .WithMany()
                      .HasForeignKey(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);

                entity.HasIndex(e => new { e.UserId, e.Token });
                entity.HasIndex(e => e.ExpiresAt);
            });

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
}

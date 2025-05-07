using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/UserSessionConfiguration.cs
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/AuditLogConfiguration.cs
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

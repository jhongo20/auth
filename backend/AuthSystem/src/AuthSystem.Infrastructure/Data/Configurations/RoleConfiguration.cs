using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/RoleConfiguration.cs
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

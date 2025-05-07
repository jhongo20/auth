using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/ModuleConfiguration.cs
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/PasswordHistoryConfiguration.cs
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class PasswordHistoryConfiguration : IEntityTypeConfiguration<PasswordHistory>
    {
        public void Configure(EntityTypeBuilder<PasswordHistory> builder)
        {
            builder.ToTable("PasswordHistory");

            builder.HasKey(ph => ph.Id);

            builder.Property(ph => ph.PasswordHash)
                .IsRequired();

            builder.Property(ph => ph.IPAddress)
                .HasMaxLength(50);

            builder.HasIndex(ph => ph.UserId);
            builder.HasIndex(ph => ph.ChangedAt);

            // Relación con User
            builder.HasOne<User>()
                .WithMany()
                .HasForeignKey(ph => ph.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/LoginAttemptConfiguration.cs
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class LoginAttemptConfiguration : IEntityTypeConfiguration<LoginAttempt>
    {
        public void Configure(EntityTypeBuilder<LoginAttempt> builder)
        {
            builder.ToTable("LoginAttempts");

            builder.HasKey(la => la.Id);

            builder.Property(la => la.Username)
                .HasMaxLength(100)
                .IsRequired();

            builder.Property(la => la.Email)
                .HasMaxLength(255);

            builder.Property(la => la.IPAddress)
                .HasMaxLength(50)
                .IsRequired();

            builder.Property(la => la.FailureReason)
                .HasMaxLength(255);

            builder.HasIndex(la => la.Username);
            builder.HasIndex(la => la.IPAddress);
            builder.HasIndex(la => la.AttemptedAt);
            builder.HasIndex(la => la.UserId);
        }
    }
}

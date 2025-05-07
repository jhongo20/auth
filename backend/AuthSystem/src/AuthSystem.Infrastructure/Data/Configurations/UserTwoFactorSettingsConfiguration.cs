using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

// Data/Configurations/UserTwoFactorSettingsConfiguration.cs
using AuthSystem.Core.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace AuthSystem.Infrastructure.Data.Configurations
{
    public class UserTwoFactorSettingsConfiguration : IEntityTypeConfiguration<UserTwoFactorSettings>
    {
        public void Configure(EntityTypeBuilder<UserTwoFactorSettings> builder)
        {
            builder.ToTable("UserTwoFactorSettings");

            builder.HasKey(tf => tf.UserId);

            builder.Property(tf => tf.Method)
                .HasMaxLength(50)
                .IsRequired();

            // Relación con User
            builder.HasOne<User>()
                .WithOne()
                .HasForeignKey<UserTwoFactorSettings>(tf => tf.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}

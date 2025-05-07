using System.ComponentModel.DataAnnotations;

namespace AuthSystem.Application.DTOs
{
    public class UserProfileDto
    {
        [Required]
        [StringLength(100)]
        public string FirstName { get; set; }

        [Required]
        [StringLength(100)]
        public string LastName { get; set; }

        [Phone]
        public string PhoneNumber { get; set; }

        public string ProfilePictureUrl { get; set; }
    }
}
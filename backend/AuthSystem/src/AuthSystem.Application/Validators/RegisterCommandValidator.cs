using AuthSystem.Application.Commands.Authentication;
using FluentValidation;
using System.Text.RegularExpressions;

namespace AuthSystem.Application.Validators.Authentication
{
    public class RegisterCommandValidator : AbstractValidator<RegisterCommand>
    {
        public RegisterCommandValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("El nombre de usuario es obligatorio.")
                .MinimumLength(4).WithMessage("El nombre de usuario debe tener al menos 4 caracteres.")
                .MaximumLength(100).WithMessage("El nombre de usuario no debe exceder los 100 caracteres.")
                .Matches("^[a-zA-Z0-9_.-]+$").WithMessage("El nombre de usuario solo puede contener letras, números, guiones, puntos y guiones bajos.");

            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("El correo electrónico es obligatorio.")
                .EmailAddress().WithMessage("El formato del correo electrónico no es válido.")
                .MaximumLength(255).WithMessage("El correo electrónico no debe exceder los 255 caracteres.");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("La contraseña es obligatoria.")
                .MinimumLength(8).WithMessage("La contraseña debe tener al menos 8 caracteres.")
                .MaximumLength(100).WithMessage("La contraseña no debe exceder los 100 caracteres.")
                .Must(password => Regex.IsMatch(password, @"[A-Z]")).WithMessage("La contraseña debe contener al menos una letra mayúscula.")
                .Must(password => Regex.IsMatch(password, @"[a-z]")).WithMessage("La contraseña debe contener al menos una letra minúscula.")
                .Must(password => Regex.IsMatch(password, @"[0-9]")).WithMessage("La contraseña debe contener al menos un número.")
                .Must(password => Regex.IsMatch(password, @"[^a-zA-Z0-9]")).WithMessage("La contraseña debe contener al menos un carácter especial.");

            RuleFor(x => x.FirstName)
                .MaximumLength(100).WithMessage("El nombre no debe exceder los 100 caracteres.");

            RuleFor(x => x.LastName)
                .MaximumLength(100).WithMessage("El apellido no debe exceder los 100 caracteres.");
        }
    }
}
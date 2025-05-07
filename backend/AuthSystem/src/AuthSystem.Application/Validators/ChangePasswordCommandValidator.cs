using AuthSystem.Application.Commands.User;
using FluentValidation;
using System;
using System.Text.RegularExpressions;

namespace AuthSystem.Application.Validators.User
{
    public class ChangePasswordCommandValidator : AbstractValidator<ChangePasswordCommand>
    {
        public ChangePasswordCommandValidator()
        {
            RuleFor(x => x.UserId)
                .NotEqual(Guid.Empty).WithMessage("El ID de usuario no es válido.");

            RuleFor(x => x.CurrentPassword)
                .NotEmpty().WithMessage("La contraseña actual es obligatoria.");

            RuleFor(x => x.NewPassword)
                .NotEmpty().WithMessage("La nueva contraseña es obligatoria.")
                .MinimumLength(8).WithMessage("La nueva contraseña debe tener al menos 8 caracteres.")
                .MaximumLength(100).WithMessage("La nueva contraseña no debe exceder los 100 caracteres.")
                .Must(password => Regex.IsMatch(password, @"[A-Z]")).WithMessage("La nueva contraseña debe contener al menos una letra mayúscula.")
                .Must(password => Regex.IsMatch(password, @"[a-z]")).WithMessage("La nueva contraseña debe contener al menos una letra minúscula.")
                .Must(password => Regex.IsMatch(password, @"[0-9]")).WithMessage("La nueva contraseña debe contener al menos un número.")
                .Must(password => Regex.IsMatch(password, @"[^a-zA-Z0-9]")).WithMessage("La nueva contraseña debe contener al menos un carácter especial.")
                .NotEqual(x => x.CurrentPassword).WithMessage("La nueva contraseña no puede ser igual a la contraseña actual.");
        }
    }
}
using AuthSystem.Application.Commands.Authentication;
using FluentValidation;

namespace AuthSystem.Application.Validators.Authentication
{
    public class AuthenticateCommandValidator : AbstractValidator<AuthenticateCommand>
    {
        public AuthenticateCommandValidator()
        {
            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("El nombre de usuario es obligatorio.")
                .MaximumLength(100).WithMessage("El nombre de usuario no debe exceder los 100 caracteres.");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("La contraseña es obligatoria.")
                .MinimumLength(8).WithMessage("La contraseña debe tener al menos 8 caracteres.")
                .MaximumLength(100).WithMessage("La contraseña no debe exceder los 100 caracteres.");

            // Las propiedades IpAddress y UserAgent serán completadas por el controlador,
            // no por el usuario, así que no las validamos aquí
        }
    }
}
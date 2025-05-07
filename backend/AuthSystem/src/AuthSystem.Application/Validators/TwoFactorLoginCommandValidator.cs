using AuthSystem.Application.Commands.Authentication;
using FluentValidation;
using System;

namespace AuthSystem.Application.Validators.Authentication
{
    public class TwoFactorLoginCommandValidator : AbstractValidator<TwoFactorLoginCommand>
    {
        public TwoFactorLoginCommandValidator()
        {
            RuleFor(x => x.UserId)
                .NotEqual(Guid.Empty).WithMessage("El ID de usuario no es válido.");

            RuleFor(x => x.Code)
                .NotEmpty().WithMessage("El código de verificación es obligatorio.")
                .MinimumLength(6).WithMessage("El código debe tener al menos 6 caracteres.")
                .MaximumLength(10).WithMessage("El código no debe exceder los 10 caracteres.");
        }
    }
}
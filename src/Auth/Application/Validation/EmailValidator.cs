using FluentValidation;

public class EmailValidator : AbstractValidator<String>
{
    public EmailValidator()
    {
        RuleFor(x => x).NotEmpty().EmailAddress().MaximumLength(50).WithName("Email");
    }
}

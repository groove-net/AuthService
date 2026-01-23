using FluentValidation;

public class UsernameValidator : AbstractValidator<String>
{
    public UsernameValidator()
    {
        RuleFor(username => username)
            .NotEmpty()
            .MaximumLength(20)
            .Matches(@"^[a-zA-Z_][a-zA-Z0-9_]*$")
            .WithMessage("Username must start with a letter or underscore and contain only alphanumeric characters or underscores.");
    }
}

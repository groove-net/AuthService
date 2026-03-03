using Auth.Domain;
using Microsoft.AspNetCore.DataProtection;

namespace Auth.Application;

// 2. Define Response
public record RegisterResult(Guid UserId);

internal class Register
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IEmailSender _emailSender;
    private readonly IDataProtector _protector;

    public Register(
        IUserRepository userRepository,
        IUnitOfWork unitOfWork,
        IEmailSender emailSender,
        IDataProtector protector)
    {
        _userRepository = userRepository;
        _unitOfWork = unitOfWork;
        _emailSender = emailSender;
        _protector = protector;
    }

    // 3. Handle method
    public async Task<Result<RegisterResult, Error>> Handle(
        string username,
        string email,
        string password)
    {
        // Validation
        var validation = new EmailValidator().Validate(email);
        if (!validation.IsValid)
            return Result<RegisterResult, Error>
              .Fail(new Error("InvalidEmail", validation.Errors.First().ErrorMessage));
        validation = new UsernameValidator().Validate(username);
        if (!validation.IsValid)
            return Result<RegisterResult, Error>
              .Fail(new Error("InvalidUsername", validation.Errors.First().ErrorMessage));
        validation = new PasswordValidator().Validate(password);
        if (!validation.IsValid)
            return Result<RegisterResult, Error>
              .Fail(new Error("InvalidPassword", validation.Errors.First().ErrorMessage));

        // Check for pre-conditions (Application logic)
        if (await _userRepository.ExistsByUsernameAsync(username))
            return Result<RegisterResult, Error>
              .Fail(new("UsernameExists", $"The username '{username}' is already registered."));
        if (await _userRepository.ExistsByEmailAsync(email))
            return Result<RegisterResult, Error>
              .Fail(new("EmailExists", $"The email address '{email}' is already registered."));

        // Create valid user object (Business logic)
        var user = new User(username, email, password);

        // User Registred Event
        user.AddDomainEvent(new UserRegisteredDomainEvent(user.Id, user.Email));

        // Persist changes (Infrastructure orchestration)
        await _userRepository.AddAsync(user);
        await _unitOfWork.SaveEntitiesAsync();

        return Result<RegisterResult, Error>.Success(new RegisterResult(user.Id));
    }

}

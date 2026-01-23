using Microsoft.AspNetCore.DataProtection;

public class RegisterUser
{
    private readonly IUserRepository _userRepository;
    private readonly IUnitOfWork _unitOfWork;
    private readonly IEmailSender _emailSender;
    private readonly IDataProtector _protector;

    public RegisterUser(
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

    // 2. Define Response
    public record Value(Guid UserId);

    // 3. Handle method
    public async Task<Result<Value, Error>> Handle(
        string username,
        string email,
        string password)
    {
        // Validation
        var validation = new EmailValidator().Validate(email);
        if (!validation.IsValid)
            return Result<Value, Error>
              .Fail(new Error("InvalidEmail", validation.Errors.First().ErrorMessage));
        validation = new UsernameValidator().Validate(username);
        if (!validation.IsValid)
            return Result<Value, Error>
              .Fail(new Error("InvalidUsername", validation.Errors.First().ErrorMessage));
        validation = new PasswordValidator().Validate(password);
        if (!validation.IsValid)
            return Result<Value, Error>
              .Fail(new Error("InvalidPassword", validation.Errors.First().ErrorMessage));

        // Check for pre-conditions (Application logic)
        if (await _userRepository.ExistsByUsernameAsync(username))
            return Result<Value, Error>
              .Fail(new("UsernameExists", $"The username '{username}' is already registered."));
        if (await _userRepository.ExistsByEmailAsync(email))
            return Result<Value, Error>
              .Fail(new("EmailExists", $"The email address '{email}' is already registered."));

        // Create valid user object (Business logic)
        var user = new User(username, email, password);

        // Persist changes (Infrastructure orchestration)
        await _userRepository.AddAsync(user);
        await _unitOfWork.SaveChangesAsync();

        // Send email confirmation token
        await new SendEmailConfirmation(
            _userRepository,
            _unitOfWork,
            _emailSender,
            _protector).Handle(user.Id);

        return Result<Value, Error>.Success(new Value(user.Id));
    }

}

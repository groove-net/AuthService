namespace Auth.Application;


internal interface IConfirmationTokenGenerator
{
    public class Payload
    {
        public Guid UserId { get; set; }
        public String UserEmail { get; set; } = default!;
        public DateTime ExpiresAt { get; set; }
    }

    String GenerateConfirmationToken(Guid userId, String userEmail);
    Payload? ValidateConfirmationToken(String token);
}

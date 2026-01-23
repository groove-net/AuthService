public interface ITwoFactorChallenge
{
    record Payload
    {
        public Guid UserId { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

    string Create(Guid userId);
    Result<Payload, Error> Validate(string challengeToken);
}

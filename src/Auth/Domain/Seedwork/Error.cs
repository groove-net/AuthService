public record class Error(string Code, string Message)
{
    public override string ToString() => Code;
}

namespace Core.Models;

public abstract record Error(string Code, string Message)
{
  public override string ToString() => Code;
}
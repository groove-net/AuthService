namespace Core.Models;

public record Result<TValue, TError>
{
  public TValue? Value { get; init; }
  public TError? Error { get; init; }
  public bool IsSuccess => Error is null;

  public static Result<TValue, TError> Success(TValue value) => new() { Value = value };
  public static Result<TValue, TError> Fail(TError error) => new() { Error = error };
}
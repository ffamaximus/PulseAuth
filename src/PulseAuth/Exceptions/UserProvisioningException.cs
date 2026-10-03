namespace PulseAuth.Exceptions;

/// <summary>
/// Thrown by <c>IUserAuthenticationService.AutoProvisionUserAsync</c> when a local account cannot
/// be created for an external login (e.g. the e-mail address already belongs to another account).
/// The token endpoint turns it into an <c>invalid_grant</c> response whose description is
/// <see cref="Exception.Message"/>, so the message must be safe to show to the client.
/// </summary>
public class UserProvisioningException : Exception
{
    /// <summary>Machine-readable reason (e.g. <c>duplicate_email</c>).</summary>
    public string Reason { get; }

    /// <summary>Creates the exception.</summary>
    public UserProvisioningException(string reason, string message, Exception? innerException = null)
        : base(message, innerException)
        => Reason = reason;
}

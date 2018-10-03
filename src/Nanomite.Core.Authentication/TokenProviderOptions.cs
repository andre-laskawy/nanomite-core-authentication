///-----------------------------------------------------------------
///   File:         TokenProviderOptions.cs
///   Author:   	Andre Laskawy           
///   Date:         30.09.2018 18:46:38
///-----------------------------------------------------------------

namespace Nanomite.Core.Authentication
{
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Security.Claims;
    using System.Threading.Tasks;

    /// <summary>
    /// Defines the <see cref="TokenProviderOptions"/>
    /// </summary>
    public class TokenProviderOptions : TokenValidationParameters
    {
        /// <summary>
        /// Gets or sets the IdentityResolver Resolves a user identity given a username and password.
        /// </summary>
        public Func<string, string, Task<ClaimsIdentity>> IdentityResolver { get; set; }

        /// <summary>
        /// Gets the JtiGenerator "jti" (JWT ID) Claim (default ID is a GUID)
        /// </summary>
        public Func<Task<string>> JtiGenerator =>
          () => Task.FromResult(Guid.NewGuid().ToString());

        /// <summary>
        /// Gets or sets the SigningCredentials The signing key to use when generating tokens.
        /// </summary>
        public SigningCredentials SigningCredentials { get; set; }

        /// <summary>
        /// Gets or sets the Subject 4.1.2. "sub" (Subject) Claim - The "sub" (subject) claim
        /// identifies the principal that is the subject of the JWT.
        /// </summary>
        public string Subject { get; set; }
    }
}

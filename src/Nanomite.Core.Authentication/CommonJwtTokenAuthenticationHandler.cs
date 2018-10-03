///-----------------------------------------------------------------
///   File:         CommonJwtTokenAuthenticationHandler.cs
///   Author:   	Andre Laskawy           
///   Date:         02.10.2018 17:11:46
///-----------------------------------------------------------------

namespace Nanomite.Core.Authentication
{
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// Defines the <see cref="CommonJwtTokenAuthenticationHandler"/>
    /// </summary>
    public class CommonJwtTokenAuthenticationHandler
    {
        /// <summary>
        /// The audience
        /// </summary>
        public const string Audience = "nanomite-solutions.com";

        /// <summary>
        /// The issuer
        /// </summary>
        public const string Issuer = "nanomite-solutions.com";

        /// <summary>
        /// Defines the symmetricSecurityKey
        /// </summary>
        private string symmetricSecurityKey;

        /// <summary>
        /// The user access function
        /// </summary>
        private Func<string, string, Task<string>> userAccessFunction;

        /// <summary>
        /// Initializes a new instance of the <see cref="CommonJwtTokenAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="userAccessFunction">The user access function.</param>
        /// <param name="secret">The secret<see cref="string"/></param>
        public CommonJwtTokenAuthenticationHandler(Func<string, string, Task<string>> userAccessFunction, string secret)
        {
            this.userAccessFunction = userAccessFunction;
            this.symmetricSecurityKey = secret;
        }

        /// <summary>
        /// Authenticates the specified client.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="pass">The password.</param>
        /// <returns>the user if the credentials are valid</returns>
        /// <inheritdoc/>
        public async Task<string> Authenticate(string clientId, string pass)
        {
            string token = await GetToken(clientId, pass);
            return token;
        }

        /// <summary>
        /// Authenticates the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns>The <see cref="Task{User}"/></returns>
        public bool Authenticate(string token)
        {
            var user = ValidateToken(token);
            if (user != null)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the JWT options.
        /// </summary>
        /// <returns></returns>
        public TokenProviderOptions GetJWTOptions()
        {
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(symmetricSecurityKey));
            return new TokenProviderOptions()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateIssuerSigningKey = true,
                RequireExpirationTime = false,
                ValidateLifetime = false,
                ClockSkew = TimeSpan.Zero,
                ValidAudience = Audience,
                ValidIssuer = Issuer,
                IssuerSigningKey = signingKey,
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256),
                IdentityResolver = (a, b) => { return GetIdentity(a, b); }
            };
        }

        /// <summary>
        /// Gets the identity.
        /// </summary>
        /// <param name="clientId">The client identifier.</param>
        /// <param name="password">The password.</param>
        /// <returns></returns>
        private async Task<ClaimsIdentity> GetIdentity(string clientId, string password)
        {
            var identitiy = await GetUserIdentity(clientId, password);
            return identitiy;
        }

        /// <summary>
        /// The GenerateToken
        /// </summary>
        /// <param name="user">The user.</param>
        /// <param name="pass">The pass.</param>
        /// <returns>The <see cref="Task{string}"/></returns>
        private async Task<string> GetToken(string user, string pass)
        {
            var options = GetJWTOptions();
            var identity = await options.IdentityResolver(user, pass);
            if (identity == null)
            {
                return null;
            }

            var now = DateTime.UtcNow;
            var claims = new Claim[]
            {
                new Claim("emails", user),
                new Claim(JwtRegisteredClaimNames.NameId, user),
                new Claim(JwtRegisteredClaimNames.Iat, new DateTimeOffset(now).ToUniversalTime().ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            // Create the JWT and write it to a string
            var jwt = new JwtSecurityToken(
                claims: claims,
                issuer: options.ValidIssuer,
                audience: options.ValidAudience,
                notBefore: now,
                expires: now.Add(new TimeSpan(1, 0, 0, 0)),
                signingCredentials: options.SigningCredentials);
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            return encodedJwt;
        }

        /// <summary>
        /// Gets the user identity.
        /// </summary>
        /// <param name="userForeignId">The <see cref="string"/></param>
        /// <param name="password">The <see cref="string"/></param>
        /// <returns>The <see cref="Task{ClaimsIdentity}"/></returns>
        private async Task<ClaimsIdentity> GetUserIdentity(string userForeignId, string password)
        {
            bool nfc = false;
            string token = await this.userAccessFunction.Invoke(userForeignId, password);

            if (string.IsNullOrEmpty(token))
            {
                return null;
            }

            return new ClaimsIdentity(new GenericIdentity(token, "Token"), new Claim[] { });
        }

        /// <summary>
        /// Validates the token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <returns></returns>
        private ClaimsPrincipal ValidateToken(string token)
        {
            TokenValidationParameters validationParameters =
            new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = false,
                IssuerSigningKeys = new List<SymmetricSecurityKey> { new SymmetricSecurityKey(Encoding.ASCII.GetBytes(symmetricSecurityKey)) }
            };

            SecurityToken validatedToken;
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            return handler.ValidateToken(token, validationParameters, out validatedToken);
        }
    }
}

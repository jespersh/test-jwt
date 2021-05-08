using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;

namespace testJwtApi1
{
    public class ExtraTokensValidator : JwtSecurityTokenHandler, IExtraTokensValidator
    {
        private readonly List<string> _tokens;
        public ExtraTokensValidator()
        {
            _tokens = new List<string>();
        }

        public void SaveToken(string rawData, DateTime validTo)
        {
            _tokens.Add(rawData);
        }

        public override ClaimsPrincipal ValidateToken(string token, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            ClaimsPrincipal claimsPrincipal = base.ValidateToken(token, validationParameters, out validatedToken);

            if (_tokens.Any(t => t == token))
            {
                return claimsPrincipal;
            }

            throw Microsoft.IdentityModel.Logging.LogHelper.LogExceptionMessage(
                new SecurityTokenExpiredException(Microsoft.IdentityModel.Logging.LogHelper.FormatInvariant("IDX10223: Lifetime validation failed. The token is expired. ValidTo: '{0}', Current time: '{1}'.", 
                validatedToken.ValidTo, DateTime.UtcNow)) { Expires = validatedToken.ValidTo });
        }
    }
}

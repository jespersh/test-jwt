using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace testJwtApi1
{
    public interface IExtraTokensValidator : ISecurityTokenValidator
    {
        SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor);
        string WriteToken(SecurityToken token);
        void SaveToken(string rawData, DateTime validTo);
    }
}

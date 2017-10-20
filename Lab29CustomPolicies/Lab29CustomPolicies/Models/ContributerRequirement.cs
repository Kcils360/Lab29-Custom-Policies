using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lab29CustomPolicies.Models
{
    public class ContributerRequirement : IAuthorizationRequirement
    {
    }
}

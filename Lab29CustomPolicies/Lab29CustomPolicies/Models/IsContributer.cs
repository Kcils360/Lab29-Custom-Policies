using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Lab29CustomPolicies.Models
{
    public class IsContributer : AuthorizationHandler<ContributerRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ContributerRequirement requirement)
        {
            if (!context.User.HasClaim(c => c.Type == ClaimTypes.Role))
            {
                return Task.CompletedTask;

            }
            if (context.User.FindFirst(c=> c.Type == ClaimTypes.))


            return Task.CompletedTask;
        }

    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;

namespace Lab29CustomPolicies.Models
{
    public class Lab29CustomPoliciesContext : DbContext
    {
        public Lab29CustomPoliciesContext (DbContextOptions<Lab29CustomPoliciesContext> options)
            : base(options)
        {
        }

        public DbSet<Lab29CustomPolicies.Models.Recipe> Recipe { get; set; }
    }
}

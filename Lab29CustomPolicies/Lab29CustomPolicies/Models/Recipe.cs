using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Lab29CustomPolicies.Models
{
    public class Recipe
    {
        public int ID { get; set; }

        public string Dish { get; set; }

        public string Category { get; set; }

        public string Ingredients { get; set; }

        public string Directions { get; set; }

        public bool IsPublished { get; set; }
    }
}

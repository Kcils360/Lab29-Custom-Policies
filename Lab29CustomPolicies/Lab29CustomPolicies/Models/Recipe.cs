using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
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

        [Display(Name = "Contains Alcohol")]
        public bool ContainsAlcohol { get; set; }

        public string Directions { get; set; }

    }
}

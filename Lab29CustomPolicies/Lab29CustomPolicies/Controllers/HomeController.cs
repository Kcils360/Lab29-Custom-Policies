using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Lab29CustomPolicies.Models;

namespace Lab29CustomPolicies.Controllers
{
    public class HomeController : Controller
    {
        private readonly Lab29CustomPoliciesContext _context;

        public HomeController(Lab29CustomPoliciesContext context)
        {
            _context = context;
        }

        public IActionResult Index()
        {
            return View();
        }
    }
}
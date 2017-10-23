using Microsoft.EntityFrameworkCore.Migrations;
using System;
using System.Collections.Generic;

namespace Lab29CustomPolicies.Migrations
{
    public partial class addedAlcBool : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsPublished",
                table: "Recipe");

            migrationBuilder.AddColumn<bool>(
                name: "ContainsAlcohol",
                table: "Recipe",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ContainsAlcohol",
                table: "Recipe");

            migrationBuilder.AddColumn<bool>(
                name: "IsPublished",
                table: "Recipe",
                nullable: false,
                defaultValue: false);
        }
    }
}

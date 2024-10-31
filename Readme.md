

# Adding jwtBearer authentication to CRUD ASP.NET MVC  application

1. Install the required dependencies 
```bash
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
```

2.  Configure Database and Identity in Program.cs file 

- Configure Identity

```bash
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();
```

- Configure JWT Authentication

```bash
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
    };
});
```

3. Configure JWT Settings in appsettings.json:

```bash
{
  "Jwt": {
    "Key": "YourSuperSecretKeyHere",
    "Issuer": "CrudAppIssuer",
    "Audience": "CrudAppAudience"
  },
  "ConnectionStrings": {
    "DefaultConnection": "YourDatabaseConnectionString"
  }
}

```

4. Modify the AppDbContext  to use IdentityDbContext instead DbContext

```bash
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using CrudApp.Models;

namespace CrudApp.Data
{
    public class AppDbContext : IdentityDbContext<IdentityUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<Note> Notes { get; set; }
    }
}
```

5. Run Migration and Update Database

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update

```

6. Create AuthController with Register and Login Actions:

```bash
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

[Route("auth")]
public class AuthController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = new IdentityUser { UserName = model.Email, Email = model.Email };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded) return RedirectToAction("Login");

        foreach (var error in result.Errors) ModelState.AddModelError("", error.Description);

        return View(model);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginModel model)
    {
        if (!ModelState.IsValid) return View(model);

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var token = GenerateJwtToken(user);
            return Ok(new { token });
        }

        ModelState.AddModelError("", "Invalid login attempt.");
        return View(model);
    }

    private string GenerateJwtToken(IdentityUser user)
    {
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}

public class RegisterModel
{
    [Required] public string Email { get; set; }
    [Required] [DataType(DataType.Password)] public string Password { get; set; }
}

public class LoginModel
{
    [Required] public string Email { get; set; }
    [Required] [DataType(DataType.Password)] public string Password { get; set; }
}

```

7. Create a new RegisterModel in Models folder

```bash
using System.ComponentModel.DataAnnotations;

namespace CrudApp.Models
{
    public class RegisterModel
{
     [Required] 
    public string? Email { get; set; }
    [Required] 
    [DataType(DataType.Password)] 
    public string? Password { get; set; }
}

}

```

8. Create a new LoginModel in Models folder

```bash
@model  CrudApp.Models.LoginModel

<form asp-action="Login" method="post">
    <div class="form-group">
        <label>Email</label>
        <input class="form-control" asp-for="Email" />
    </div>
    <div class="form-group">
        <label>Password</label>
        <input class="form-control" asp-for="Password" type="password" />
    </div>
    <button class="btn btn-warning mt-2" type="submit">Login</button>
</form>


```

9. Create Views for Register and Login
- In your Views/Auth folder, create the following views.

- Register View (Register.cshtml):

```bash
@model  CrudApp.Models.RegisterModel

<form asp-action="Register" method="post">
    <div class="form-group">
        <label asp-for="Email" >Email</label>
        <input class="form-control" asp-for="Email" />
    </div>
    <div class="form-group">
        <label asp-for="Password" >Password</label>
        <input class="form-control" asp-for="Password" type="password" />
        <span asp-asp-validation-for="password" class="text-danger"></span>
    </div>
    <button class="btn btn-warning mt-2" type="submit">Register</button>
</form>
```

2.   Login View (Login.cshtml):

```bash
@model LoginModel

<form asp-action="Login" method="post">
    <div>
        <label>Email</label>
        <input asp-for="Email" />
    </div>
    <div>
        <label>Password</label>
        <input asp-for="Password" type="password" />
    </div>
    <button type="submit">Login</button>
</form>

```

10. Secure the CRUD Controller

- Add [Authorize] to your CRUD actions to require a valid token for access.
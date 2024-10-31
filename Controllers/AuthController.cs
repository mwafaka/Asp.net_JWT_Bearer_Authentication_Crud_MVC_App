using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.ComponentModel.DataAnnotations;
using CrudApp.Models; 

/* [Route("auth")]
[ApiController] */
public class AuthController : Controller
{
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthController> _logger;
    public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration,ILogger<AuthController> logger)
    {
        _userManager = userManager;
        _configuration = configuration;
         _logger = logger;
    }

    // GET: Notes/Register
  /*   [HttpGet("register")] */
    public IActionResult Register()
    {
        return View();
    }



    [HttpPost]
    public async Task<IActionResult> Register( RegisterModel model)
    {
       
         /*  if (!ModelState.IsValid) return View(model); */  

        var user = new IdentityUser { UserName = model.Email, Email = model.Email };


        var result = await _userManager.CreateAsync(user, model.Password);
System.Console.WriteLine(result);
        if (result.Succeeded) return RedirectToAction("Login");

        foreach (var error in result.Errors) ModelState.AddModelError("", error.Description);

        return View(model);
    }

    // GET: Notes/Register
    /* [HttpGet("login")] */
    public IActionResult Login()
    {
        return View();
    }


    [HttpPost]
    public async Task<IActionResult> Login(LoginModel model)
    {

     if (!ModelState.IsValid) return View(model);

        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
        {
            var token = GenerateJwtToken(user);

             // Set the token as an HttpOnly cookie
    HttpContext.Response.Cookies.Append("jwt", token, new CookieOptions
    {
        HttpOnly = true,
        Secure = true, // Set to true in production
        SameSite = SameSiteMode.Strict
    });
             Ok(new { token });
            return RedirectToAction("Index","Notes");
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



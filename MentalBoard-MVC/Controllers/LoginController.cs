using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using MentalBoard_MVC.DTO;
using MentalBoard_MVC.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

namespace MentalBoard_MVC.Controllers
{
    public class LoginController : Controller
    {
        private readonly ClaimsPrincipal principal;
        JwtSecurityToken jwtSecurityToken;
        string resultado = null;
        static readonly HttpClient client = new HttpClient();
        private readonly IConfiguration Configuration;

        public LoginController(IConfiguration configuration)
        {
            this.Configuration = configuration;
        }
        public IActionResult Index()
        {
            return View();
        }

        public async Task<IActionResult> Login([FromForm] AppUser login)
        {
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(Configuration["baseAddress"]);
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(
            new MediaTypeWithQualityHeaderValue("application/json"));
            try
            {
                AppUser user = new AppUser
                {
                    UserName = login.UserName,
                    PasswordHash = login.PasswordHash,
                };

                var contenido = await client.PostAsJsonAsync(client.BaseAddress + "api/AppUsers/Login", user);

                if (contenido.IsSuccessStatusCode)
                {

                    string resultado = await (contenido.Content.ReadAsStringAsync());
                    JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                    AppUserDTO logToken = JsonConvert.DeserializeObject<AppUserDTO>(resultado);
                    JwtSecurityToken secToken = handler.ReadJwtToken(logToken.token);

                    var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
                    identity.AddClaims(secToken.Claims);
                    var principal = new ClaimsPrincipal(identity);
                    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);
                    return RedirectToAction("Home", "Home");
                }
                else
                {
                    resultado = null;
                    ViewBag.Message = "Usuario o contraseña incorrecto.";
                    return View("Index");
                }
            }
            catch (Exception e)
            {
                return await Task.Run(() => BadRequest(e));

            }
        }
    }
}
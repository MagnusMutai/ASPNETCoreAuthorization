using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);
const string AuthScheme = "çookie";
const string AuthScheme2 = "çookie2";

// Add services to the container.
builder.Services.AddRazorPages();

//policies configuration
builder.Services.AddAuthorization(builder =>
{
   builder.AddPolicy("eu passport", pb =>
   {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(AuthScheme)
            .AddRequirements()
            .RequireClaim("passport_type", "eurr");
   }); 
});

builder.Services.AddAuthentication(AuthScheme)
    .AddCookie(AuthScheme)
    .AddCookie(AuthScheme2);

var app = builder.Build();

//middlewares
app.UseAuthentication();
app.UseAuthorization();

// app.Use((ctx, next) =>
// {
//     if(ctx.Request.Path.StartsWithSegments("/login"))
//     {
//         return next();
//     }

//     if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
//     {
//       ctx.Response.StatusCode = 401;
//       return Task.CompletedTask;
//     }

//      if(!ctx.User.HasClaim("passport_type", "eur"))
//     {
//         ctx.Response.StatusCode = 403;
//         return Task.CompletedTask;
//     }

//     return next();
// });

// [Authorize(Policy = "eu passport")]
app.MapGet("/unsecure", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? "empty";
});

app.MapGet("/sweden", (HttpContext ctx) =>
{
    // if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    // {
    //   ctx.Response.StatusCode = 401;
    //   return "";
    // }

    // if(!ctx.User.HasClaim("passport_type", "eur"))
    // {
    //     ctx.Response.StatusCode = 403;
    //     return "";
    // }
    
    return "allowed";
}).RequireAuthorization("eu passport");

app.MapGet("/norway", (HttpContext ctx) =>
{
    // if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
    // {
    //   ctx.Response.StatusCode = 401;
    //   return "";
    // }

    // if(!ctx.User.HasClaim("passport_type", "NOR"))
    // {
    //     ctx.Response.StatusCode = 403;
    //     return "";
    // }
    return "allowed";
});

// [AuthScheme(AuthScheme2)]
// [AuthClaim("passport_type", "eur")]
app.MapGet("/denmark", (HttpContext ctx) =>
{
    // if(!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme2))
    // {
    //   ctx.Response.StatusCode = 401;
    //   return "";
    // }

    // if(!ctx.User.HasClaim("passport_type", "eur"))
    // {
    //     ctx.Response.StatusCode = 403;
    //     return "";
    // }
    return "allowed";
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "magnus"));
     claims.Add(new Claim("passport_type", "eur"));
    var identity = new ClaimsIdentity(claims, AuthScheme);
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(AuthScheme, user);
}).AllowAnonymous();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapRazorPages();

app.Run();

public class MyRequirement : IAuthorizationRequirement{}

public class MyRequirementHandler : AuthorizationHandler<MyRequirement>
{
    public MyRequirementHandler ()
    {
        
    }
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
    {
       //context.User
       //context.Succeed(new MyRequirement());
       return Task.CompletedTask;
    }
}
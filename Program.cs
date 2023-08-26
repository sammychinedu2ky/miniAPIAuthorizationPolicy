using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);
// Add Bearer Token Authentication Handler
builder.Services.AddAuthentication().AddBearerToken(IdentityConstants.BearerScheme);

// Add Authorization Policy and add a requirement to the policy
// Decided to add the policy name to the requirement class
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(EmailContainsRequirement.Policy, x =>
    {
        x.AddRequirements(new EmailContainsRequirement("sam"));
    });
});

// Add the requirement handler to the service collection
builder.Services.AddSingleton<IAuthorizationHandler, EmailContainsHandler>();
builder.Services.AddDbContext<ApplicationDbContext>(x => x.UseSqlite("DataSource=datastore.db"));
builder.Services.AddIdentityCore<IdentityUser>()
   .AddEntityFrameworkStores<ApplicationDbContext>()
   .AddApiEndpoints();
var app = builder.Build();

// registers the Identity API endpoints
app.MapIdentityApi<IdentityUser>();

// Add a route that requires the EmailContainsRequirement.Policy Policy
// The policy is added to the route using the RequireAuthorization method
app.MapGet("/contains-sam",  (ClaimsPrincipal principal) =>
{
    var email = principal.FindFirstValue(ClaimTypes.Email);
    return $"Your Email is : {email}";

}).RequireAuthorization(EmailContainsRequirement.Policy);

app.Run();

public class ApplicationDbContext : IdentityDbContext<IdentityUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options) { }
}

// The EmailContainsRequirement class sets the substring to search for in the email
// of the authenticated user.
public class EmailContainsRequirement(string substring) : IAuthorizationRequirement
{
    public string SubString = substring;
    public const string Policy = "EmailContainsSubStringPolicy";
}

// The EmailContainsHandler class checks if the authenticated user's email contains
// the substring specified in the requirement.
public class EmailContainsHandler : AuthorizationHandler<EmailContainsRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, EmailContainsRequirement requirement)
    {
        if (context.User.FindFirstValue(ClaimTypes.Email).Contains(requirement.SubString))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}

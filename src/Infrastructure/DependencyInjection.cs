using System.Security.Claims;
using System.Text;
using CleanArchitecture.Application;
using CleanArchitecture.Application.Common.Interfaces;
using CleanArchitecture.Domain.Constants;
using CleanArchitecture.Infrastructure.Data;
using CleanArchitecture.Infrastructure.Data.Interceptors;
using CleanArchitecture.Infrastructure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

public static class DependencyInjection
{
    public static void AddInfrastructureServices(this IHostApplicationBuilder builder)
    {
        var connectionString = builder.Configuration.GetConnectionString("CleanArchitectureDb");
        Guard.Against.Null(connectionString, message: "Connection string 'CleanArchitectureDb' not found.");

        builder.Services.AddScoped<ISaveChangesInterceptor, AuditableEntityInterceptor>();
        builder.Services.AddScoped<ISaveChangesInterceptor, DispatchDomainEventsInterceptor>();

        builder.Services.AddDbContext<ApplicationDbContext>((sp, options) =>
        {
            options.AddInterceptors(sp.GetServices<ISaveChangesInterceptor>());
#if (UsePostgreSQL)
            options.UseNpgsql(connectionString);
#elif (UseSqlite)
            options.UseSqlite(connectionString);
#else
            options.UseSqlServer(connectionString);
#endif
            options.ConfigureWarnings(warnings => warnings.Ignore(RelationalEventId.PendingModelChangesWarning));
        });

#if (UseAspire)
#if (UsePostgreSQL)
        builder.EnrichNpgsqlDbContext<ApplicationDbContext>();
#elif (UseSqlServer)
        builder.EnrichSqlServerDbContext<ApplicationDbContext>();
#endif
#endif

        builder.Services.AddScoped<IApplicationDbContext>(provider => provider.GetRequiredService<ApplicationDbContext>());

        builder.Services.AddScoped<ApplicationDbContextInitialiser>();

#if (UseApiOnly)

        var applicationSettings = builder.Configuration.GetSection(nameof(ApplicationSettings));

        builder.Services.AddAuthentication()
            .AddBearerToken(IdentityConstants.BearerScheme);

        builder.Services.AddAuthorizationBuilder();

        builder.Services
             //.AddIdentityCore<ApplicationUser>()
             //.AddRoles<IdentityRole>()
            .AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddApiEndpoints();

        builder.Services
            .TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());

        builder.Services
             .AddAuthentication()
            .AddScheme<JwtBearerOptions, JwtBearerHandler>(JwtBearerDefaults.AuthenticationScheme, bearer =>
            {
                bearer.RequireHttpsMetadata = false;
                bearer.SaveToken = false;

                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(
                        applicationSettings.GetValue<string>(nameof(ApplicationSettings.SecurityTokenDescriptorKey))!.PadRight((256 / 8), '\0'))),
                    ValidateIssuer = false,
                    ValidateAudience = false,

                    RequireExpirationTime = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
                };
            });

        builder.Services
            .AddAuthorizationBuilder()
            .AddPolicy(JwtBearerDefaults.AuthenticationScheme, builder =>
            {
                builder
                 .RequireAuthenticatedUser()
                 .RequireClaim(ClaimTypes.NameIdentifier)
                 .RequireRole(Roles.Administrator);
            });
#else
        builder.Services
            .AddDefaultIdentity<ApplicationUser>()
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>();
#endif

        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddTransient<IIdentityService, IdentityService>();

        builder.Services.AddAuthorization(options =>
            options.AddPolicy(Policies.CanPurge, policy => policy.RequireRole(Roles.Administrator)));
    }
}

using Azure.AI.OpenAI;
using Azure.Core;
using Azure.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenAI.Chat;

var builder = WebApplication.CreateBuilder(args);

builder.Services.BindConfiguration<AOAIConfig>("AOAI");
builder.Services.AddSingleton<TokenCredential>((services) => new AzureCliCredential());
builder.Services.AddSingleton<ChatClient>((services) =>
{
    var config = services.GetRequiredService<AOAIConfig>();
    var credential = services.GetRequiredService<TokenCredential>();
    var client = new AzureOpenAIClient(new Uri(config.Endpoint), credential);
    return client.GetChatClient(config.Deployment);
});
builder.Services.AddSingleton<IUrlScanner, MockUrlScanner>();
builder.Services.AddSingleton<PhishingDetector>();

var app = builder.Build();

app.MapPost("/api/phish", async (HttpContext context, [FromServices] PhishingDetector detector) =>
{
    using StreamReader reader = new(context.Request.Body);
    var email = await reader.ReadToEndAsync();
    var result = await detector.DetectAsync(email);
    return result;
});
app.Run();




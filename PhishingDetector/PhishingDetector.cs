using System.Text.Json;
using System.Text.Json.Schema;
using OpenAI.Chat;

public record PhishResult(
    bool Suspicious,
    string ShortDescription,
    PhishResultItem[] DetectedItems
);
public record PhishResultWithUrlChecks(
        bool Suspicious,
    string ShortDescription,
    PhishResultItem[] DetectedItems,
    Dictionary<string, string> UrlChecks
)
{
    public PhishResultWithUrlChecks(PhishResult result, Dictionary<string, string> urls)
        : this (result.Suspicious, result.ShortDescription, result.DetectedItems,urls)
        {}
}
public record PhishResultItem(
    string Title,
    string Description,
    string Reasoning
);
public record UrlCheckToolCall(string url);

public class PhishingDetector(ChatClient _chatClient, ILogger<PhishingDetector> _logger)
{
    private readonly string _prompt = """
    You are a phishing detection agent.
    Given an email, you need to determine if it is a phishing email or not.
    You should mark an email as suspicious if has the possibility of being a phishing email.
    The short description should be a single non-technical sentence describing why the email is suspicious, giving examples containing the actual text of what you found in the email, in a way that a non-technical person would understand.
    The detected items should be a list of the specific items in the email that you found suspicious.
    Each detected item should have a title (a short description of the item), a description (a longer technical description of the item), and reasoning (why you found the item suspicious).
    Include all detected items you see within an email, including common phishing techniques like suspicious URLs, attachments, requests for personal information, etc.
    Any URLs in the email should be checked for malicious content.
    """;
    public async Task<PhishResultWithUrlChecks> DetectAsync(string email)
    {
        _logger.LogInformation("Detecting phishing email...");
        Dictionary<string, string> urlChecks = [];
        var options = new ChatCompletionOptions
        {
            ResponseFormat = ChatResponseFormat.CreateJsonSchemaFormat(
                nameof(PhishResult),
                jsonSchema: BinaryData.FromString(JsonSchemaExporter.GetJsonSchemaAsNode(JsonSerializerOptions.Web, typeof(PhishResult), new JsonSchemaExporterOptions() { TreatNullObliviousAsNonNullable = true }).ToString()),
                jsonSchemaFormatDescription: "Phishing result",
                jsonSchemaIsStrict: false
            ),
            AllowParallelToolCalls = false,
            ToolChoice = ChatToolChoice.CreateAutoChoice(),
            Tools = {
                ChatTool.CreateFunctionTool(
                    "checkUrl",
                    "Check a url to see if it is potentially malicious, must be run for every url in an email",
                    BinaryData.FromString(JsonSchemaExporter.GetJsonSchemaAsNode(JsonSerializerOptions.Web, typeof(UrlCheckToolCall), new JsonSchemaExporterOptions() { TreatNullObliviousAsNonNullable = true }).ToString()),
                    false
                )
            }
        };
        List<ChatMessage> messages = [
            ChatMessage.CreateSystemMessage(_prompt),
            ChatMessage.CreateUserMessage(email)
        ];
        while (true)
        {
            var result = await _chatClient.CompleteChatAsync(messages, options);
            if (result.Value.FinishReason == ChatFinishReason.Stop)
            {
                var phishResult = JsonSerializer.Deserialize<PhishResult>(result.Value.Content[0].Text, JsonSerializerOptions.Web)
                    ?? throw new Exception("Unable to deserialize PhishResult");
                _logger.LogInformation("Phishing result: {result}", phishResult);
                return new PhishResultWithUrlChecks(phishResult, urlChecks);
            }
            else if (result.Value.FinishReason == ChatFinishReason.ToolCalls)
            {
                messages.Add(ChatMessage.CreateAssistantMessage(result.Value));
                foreach (var toolCall in result.Value.ToolCalls)
                {
                    _logger.LogInformation("Tool call: {tool}", toolCall.FunctionName);
                    if (toolCall.FunctionName == "checkUrl")
                    {
                        var urlCheckToolCall = JsonSerializer.Deserialize<UrlCheckToolCall>(toolCall.FunctionArguments.ToString());
                        var url = urlCheckToolCall?.url;
                        if (url == null)
                        {
                            throw new Exception("Unable to deserialize UrlCheckToolCall");
                        }
                        _logger.LogInformation("Checking url: {url}", url);
                        var checkResult = await CheckUrlAsync(url);
                        urlChecks.Add(url, checkResult);
                        _logger.LogInformation("Url check result: {result}", checkResult);
                        messages.Add(ChatMessage.CreateToolMessage(toolCall.Id, checkResult));
                    }
                    else
                    {
                        throw new Exception("Unexpected tool call: " + toolCall.FunctionName);
                    }
                }
            }
            else
            {
                throw new Exception("Unexpected finish reason: " + result.Value.FinishReason);
            }
        }
    }
    public async Task<string> CheckUrlAsync(string url)
    {
        // This is a placeholder for a real implementation
        return "URL is malicious";
    }
}

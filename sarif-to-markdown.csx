#!/usr/bin/env dotnet-script

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var md = new StringBuilder();
md.Append(@"# :lock_with_ink_pen: PageUp Security Code Scan
");

var hasDotnetEditorConfig = false;
var editorConfigPaths = Directory.GetFiles(Directory.GetCurrentDirectory(), ".editorconfig", SearchOption.AllDirectories);
foreach (var editorConfigPath in editorConfigPaths)
{
    using var r = new StreamReader(editorConfigPath);
    if (r.ReadToEnd().Contains("dotnet_diagnostic.CA2352.severity = error"))
    {
        hasDotnetEditorConfig = true;
        break;
    }
}

if (!hasDotnetEditorConfig)
{
    md.Append(@"### :heavy_exclamation_mark: No `.editorconfig` file detected. Please add it to your repo!
");
}

var securityCodeScanSarifs = new List<string>();
var filePaths = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.sarif", SearchOption.AllDirectories);
foreach (var filePath in filePaths)
{
    var filename = Path.GetFileName(filePath);
    if (filename.Equals("ErrorLog.csproj.sarif")) continue;

    securityCodeScanSarifs.Add(filename);
    CreateResult(filePath, md, filename);
}

var csprojFilePaths = Directory.GetFiles(Directory.GetCurrentDirectory(), "ErrorLog.csproj.sarif", SearchOption.AllDirectories);
foreach (var filePath in csprojFilePaths)
{
    var filename = $"{Path.GetFileName(Path.GetDirectoryName(filePath))}.csproj";
    if (securityCodeScanSarifs.Contains(filename)) continue;

    CreateResult(filePath, md, filename);
}

await File.WriteAllTextAsync("code-coverage-results.md", md.ToString());

void CreateResult(string filePath, StringBuilder sb, string fileName)
{
    using var r = new StreamReader(filePath);
    var json = r.ReadToEnd();

    var securityScan = JsonSerializer.Deserialize<SecurityScan>(json);
    sb.Append(@$"
## Results for `{fileName}`
");

    if (securityScan?.Runs.FirstOrDefault()?.Results.Count > 0)
    {
        sb.Append(@"
### :bug: Potential security issues have been found, please review your code.
");

        sb.Append(@"
<details><summary>Results</summary>
");
        foreach (var run in securityScan.Runs)
        {
            var tool = securityScan.Runs.FirstOrDefault()?.Tool;
            foreach (var result in run.Results)
            {
                sb.Append(CreateResultInfo(result, tool));
            }
        }

        sb.Append(@"
</details>
");
    }
    else
    {
        sb.Append(@"
#### :heavy_check_mark: No security issues have been found.
");
    }
}

string CreateResultInfo(Result result, Tool tool)
{
    var rule = tool.Driver.Rules.FirstOrDefault(x => x.Id == result.RuleId);
    var location = result.Locations.FirstOrDefault();
    return $@"
#### {rule?.Properties?.Category}: **{result.RuleId}** (severity: **{result.Level}**)

##### {rule?.FullDescription?.Text}

> {result.Message.Text}

```
{location?.PhysicalLocation?.ArtifactLocation?.Uri}#L{location?.PhysicalLocation?.Region?.StartLine}
```

[More information on {result.RuleId}]({rule?.HelpUri})

<details><summary>Details</summary>
<pre>{JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true })}</pre>
</details>

";
}


public class SecurityScan
{
    [JsonPropertyName("$schema")]
    public Uri Schema { get; set; }

    [JsonPropertyName("version")]
    public string Version { get; set; }

    [JsonPropertyName("runs")]
    public List<Run> Runs { get; set; }
}

public class Run
{
    [JsonPropertyName("results")]
    public List<Result> Results { get; set; }

    [JsonPropertyName("tool")]
    public Tool Tool { get; set; }

    [JsonPropertyName("columnKind")]
    public string ColumnKind { get; set; }
}

public class Result
{
    [JsonPropertyName("ruleId")]
    public string RuleId { get; set; }

    [JsonPropertyName("ruleIndex")]
    public long RuleIndex { get; set; }

    [JsonPropertyName("level")]
    public string Level { get; set; }

    [JsonPropertyName("message")]
    public Message Message { get; set; }

    [JsonPropertyName("locations")]
    public List<Location> Locations { get; set; }

    [JsonPropertyName("properties")]
    public ResultProperties Properties { get; set; }

    [JsonPropertyName("relatedLocations")]
    public List<Location> RelatedLocations { get; set; }
}

public class Location
{
    [JsonPropertyName("physicalLocation")]
    public PhysicalLocation PhysicalLocation { get; set; }
}

public class PhysicalLocation
{
    [JsonPropertyName("artifactLocation")]
    public ArtifactLocation ArtifactLocation { get; set; }

    [JsonPropertyName("region")]
    public Region Region { get; set; }
}

public class ArtifactLocation
{
    [JsonPropertyName("uri")]
    public string Uri { get; set; }
}

public class Region
{
    [JsonPropertyName("startLine")]
    public long StartLine { get; set; }

    [JsonPropertyName("startColumn")]
    public long StartColumn { get; set; }

    [JsonPropertyName("endLine")]
    public long EndLine { get; set; }

    [JsonPropertyName("endColumn")]
    public long EndColumn { get; set; }
}

public class Message
{
    [JsonPropertyName("text")]
    public string Text { get; set; }
}

public class ResultProperties
{
    [JsonPropertyName("warningLevel")]
    public long WarningLevel { get; set; }
}

public class Tool
{
    [JsonPropertyName("driver")]
    public Driver Driver { get; set; }
}

public class Driver
{
    [JsonPropertyName("name")]
    public string Name { get; set; }

    [JsonPropertyName("version")]
    public string Version { get; set; }

    [JsonPropertyName("dottedQuadFileVersion")]
    public string DottedQuadFileVersion { get; set; }

    [JsonPropertyName("semanticVersion")]
    public string SemanticVersion { get; set; }

    [JsonPropertyName("language")]
    public string Language { get; set; }

    [JsonPropertyName("rules")]
    public List<Rule> Rules { get; set; }
}

public class Rule
{
    [JsonPropertyName("id")]
    public string Id { get; set; }

    [JsonPropertyName("shortDescription")]
    public Message ShortDescription { get; set; }

    [JsonPropertyName("fullDescription")]
    public Message FullDescription { get; set; }

    [JsonPropertyName("helpUri")]
    public Uri HelpUri { get; set; }

    [JsonPropertyName("properties")]
    public RuleProperties Properties { get; set; }
}

public class RuleProperties
{
    [JsonPropertyName("category")]
    public string Category { get; set; }
}
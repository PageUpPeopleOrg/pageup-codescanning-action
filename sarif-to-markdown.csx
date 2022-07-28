#!/usr/bin/env dotnet-script

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var files = Directory.GetFiles(Directory.GetCurrentDirectory(), "*.sarif", SearchOption.AllDirectories);
var md = new StringBuilder();
foreach (var file in files)
{
    using var r = new StreamReader(file);
    var json = r.ReadToEnd();
    
    var securityScan = JsonSerializer.Deserialize<SecurityScan>(json);
    md.Append($"# PageUp Security Code Scan Results for {Path.GetFileName(file).Replace(".sarif", "")}");

    if (securityScan?.Runs.FirstOrDefault()?.Results.Count > 0)
    {
        md.Append(@"

## :bug: Potential security issues have been found, please review your code.

");

        foreach (var run in securityScan.Runs)
        {
            var tool = securityScan.Runs.FirstOrDefault()?.Tool;
            foreach (var result in run.Results)
            {
                md.Append(CreateResultInfo(result, tool));
            }
        }
    }
    else
    {
        md.Append(@"

### :heavy_check_mark: No security issues have been found.

");
    }
}

await File.WriteAllTextAsync("code-coverage-results.md", md.ToString());



string CreateResultInfo(Result result, Tool tool)
{
    var rule = tool.Driver.Rules.FirstOrDefault(x => x.Id == result.RuleId);
    var location = result.Locations.FirstOrDefault();
    return $@"

### {rule?.Properties?.Category}: **{result.RuleId}** (severity: **{result.Level}**)

#### {rule?.FullDescription?.Text}

> {result.Message.Text}

```
{location?.PhysicalLocation?.ArtifactLocation?.Uri}#L{location?.PhysicalLocation?.Region?.StartLine}
```

[More information on {result.RuleId}]({rule?.HelpUri})

<details><summary>Details</summary>
<pre>{JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true })}</pre></details>

------------------

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
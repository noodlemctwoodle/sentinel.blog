#PS Script for the conversion
$jsonConversionDepth = 50
$validParserPath = "D:\Repo\GitHub-Azure-Sentinel-2\sentinel-content-2\Parsers\ARM\FileEventEmpty\FileEventEmpty.json";
foreach ($file in (Get-Item ***\*.json)) {
    try {
        $parser = Get-Content -Path $validParserPath | ConvertFrom-Json -Depth $jsonConversionDepth
        $currentParser = Get-Content $file.FullName | ConvertFrom-Json -Depth $jsonConversionDepth
        $parser.resources[0].properties = $currentParser.resources[0].resources[0].properties 
        $parser.resources[0].name = "[concat(parameters('workspace'), '/" + $currentParser.resources[0].resources[0].name + "')]"
        $parser | ConvertTo-Json -EscapeHandling Default -Depth $jsonConversionDepth | Set-Content -Path ".\Sample\$($file.Name)"
    }
    catch {
        "Error on process file: $($file.FullName)" 
    }
}
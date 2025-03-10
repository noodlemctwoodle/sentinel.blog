# Microsoft 365 Defender Event Collector Function

A production-ready Azure Function that automates the collection and forwarding of Microsoft 365 Defender (MDE) security events to third-party Security Information and Event Management (SIEM) solutions via Azure Event Hub. The function leverages the Microsoft Graph API to query Advanced Hunting data efficiently, featuring enterprise-grade capabilities such as rate limiting, error handling, and event deduplication.

## Key Features

- Automated Event Collection: Collect Microsoft 365 Defender security events automatically.
- Configurable Queries: Predefined queries for antivirus detections, security alerts, and alert evidence, customisable as needed.
- Event Deduplication: Ensure no duplicate events are processed.
- Rate Limiting: Protect against API rate limits with exponential backoff.
- Batch Processing: Process events in batches for optimal performance.
- Event Hub Integration: Forward collected events to Azure Event Hub for downstream processing.

## Prerequisites

### Requirements

1. Azure Subscription
2. Azure Function App
3. Microsoft 365 E5 Security License (or equivalent with Advanced Hunting access)
4. Azure AD App Registration with appropriate permissions
5. Azure Event Hub

### Permissions

The Azure AD application requires the following Microsoft Graph API Application permissions:

-`ThreatHunting.Read.All`

## Configuration

### Environment Variables

Set the following environment variables in your Azure Function:

- TenantId: Entra ID Directory ID
- ClientId: Entra ID App Registration Client ID
- ClientSecret: Entra ID App Registration Secret

### Query Customization

Modify or extend the predefined queries in the $queries array. Default queries include:

1. Antivirus Detections
2. Security Alerts (excluding DLP)
3. Alert Evidence (excluding DLP)

### Timing and Batch Configuration

- $batchSize: Maximum records per API request (default: 10,000; maximum: 15,000).
- $lookbackMinutes: Historical data collection window (default: 5 minutes).

## Output Configuration

### Event Hub Binding

The Azure Function uses an Event Hub output binding to forward events. Each forwarded event includes:

```JSON
{
  "QueryName": "AntivirusDetection",
  "Data": {
    // Raw event data from Microsoft 365 Defender
  },
  "Timestamp": "2024-03-21T10:30:00.0000000Z"
}
```

### Required Application Settings

- Event Hub Connection String: MDE-Demo-NameSpace_RootManageSharedAccessKey_EVENTHUB
- Event Hub Name: defenderdatahub

## Function Configuration

`function.json`

Define the timer trigger and Event Hub output binding in the function.json file:

```JSON
{
  "bindings": [
    {
      "name": "Timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 */5 * * * *"
    },
    {
      "name": "MDEEvents",
      "type": "eventHub",
      "direction": "out",
      "connection": "MDE-Demo-NameSpace_RootManageSharedAccessKey_EVENTHUB",
      "eventHubName": "defenderdatahub"
    }
  ]
}
```

### Timer Trigger Schedule

- Every 5 minutes: `0 */5 * * * *` (default)
- Every 30 minutes: `0 */30 * * * *`
- Hourly: `0 0 * * * *`
- Every 6 hours: `0 0 */6 * * *`

### Error Handling

The function includes robust error-handling mechanisms:

1. Rate Limiting: Handles 429 responses with exponential backoff and retries.
2. Authentication Errors: Validates credentials and retries if needed.
3. Logging: Logs errors for failed queries, API calls, or event processing.
4. Batch Processing Protection: Ensures incomplete batches don’t corrupt data collection.

## Rate Limiting Protection

The function implements rate limiting protection to handle Microsoft Graph API's throttling mechanisms:

### HTTP 429 Response Handling

When the Microsoft Graph API returns a HTTP 429 status code ("Too Many Requests"), the function:

1. Captures the response using `$_.Exception.Response.StatusCode -eq 429`
2. Extracts the recommended wait time from the "Retry-After" header
3. Implements exponential backoff with a default 12-second delay if no wait time is specified
4. Retries the request up to 3 times

Example of the rate limiting code:
```powershell
if ($_.Exception.Response.StatusCode -eq 429) {
    $retryAfter = 12 # Default delay if header not present
    if ($_.Exception.Response.Headers["Retry-After"]) {
        $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
    }
    Write-Host "Rate limit encountered. Waiting $retryAfter seconds..."
    Start-Sleep -Seconds $retryAfter
    $retryCount++
}
```

#### Rate Limiting Best Practices

1. The function implements a 2-second delay between batch requests
2. Respects the API's Retry-After header values
3. Uses exponential backoff for repeated rate limit encounters
4. Logs all rate limiting events for monitoring

## Monitoring

### Logs

- Authentication Status: Logs authentication success/failure.
- Query Execution: Logs query execution results and any errors.
- Rate Limiting: Tracks API rate-limit encounters.
- Batch Metrics: Monitors batch processing statistics.
- Event Status: Logs successful/failed event forwarding to Event Hub.

### Key Monitoring Points

- API authentication issues.
- Data collection gaps.
- Rate-limit adjustments.
- Event Hub throughput and processing.

## Troubleshooting

### Common Issues

1. Authentication Failures
   - Verify environment variables are correct.
   - Check App Registration permissions.
   - Ensure the client secret hasn’t expired.

2. Rate Limiting
   - Reduce batch size.
   - Increase the timer trigger interval.
   - Optimize queries for efficiency.

3. Missing Data
   - Validate query timeframes.
   - Confirm permissions.
   - Review error logs for insights.

4. Event Hub Connectivity
   - Check the Event Hub connection string.
   - Verify the Event Hub namespace and instance are active.
   - Ensure the output binding is configured correctly.

## Best Practices

1. Optimise Queries: Regularly review and optimise queries for accuracy and performance.
2. Monitor Throughput: Track Event Hub throughput to avoid throttling.
3. Regular Backups: Backup function configuration and logs.
4. Credentials Management: Rotate secrets regularly and secure them.
5. Error Reviews: Monitor logs for collection gaps or recurring issues.

### Version History

- 1.0.0: Initial release.
- 1.0.1: Added rate limiting protection.
- 1.1.0: Enhanced error handling and monitoring.

License

This project is licensed under the MIT License.

Contributing

Submit issues or feature requests via the repository’s issue tracker. Contributions are welcome!

Support

1. Review Azure Function logs for error details.
2. Open an issue with relevant logs and error descriptions.
3. Contact your organisation’s Azure support team for assistance.

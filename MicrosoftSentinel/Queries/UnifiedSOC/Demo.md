# KQL Security Analysis Queries

## 1. Basic JOIN - Alert to Incident Correlation

```kql
// Join alerts with their corresponding security incidents
AlertInfo
| join kind=inner (
    SecurityIncident
    | where TimeGenerated > ago(30d)
) on TenantId
| where AlertInfo.Timestamp between (SecurityIncident.FirstActivityTime .. SecurityIncident.LastActivityTime)
| project 
    AlertId,
    AlertTitle = AlertInfo.Title,
    AlertSeverity = AlertInfo.Severity,
    IncidentNumber,
    IncidentTitle = SecurityIncident.Title,
    IncidentStatus = SecurityIncident.Status,
    AlertTimestamp = AlertInfo.Timestamp,
    IncidentCreated = SecurityIncident.CreatedTime
```

## 2. MATERIALIZE with Complex Analysis

```kql
// Materialize high-severity alerts for multiple analyses
let HighSeverityAlerts = materialize(
    AlertInfo
    | where TimeGenerated > ago(7d)
    | where Severity in ("High", "Critical")
    | where isnotempty(AlertId)
);
// Analysis 1: Count by detection source
let DetectionSourceStats = HighSeverityAlerts
    | summarize AlertCount = count(), UniqueAttackTechniques = dcount(AttackTechniques) by DetectionSource;
// Analysis 2: Timeline analysis
let TimelineStats = HighSeverityAlerts
    | summarize HourlyAlerts = count() by bin(Timestamp, 1h);
// Combine results
DetectionSourceStats
| extend AnalysisType = "DetectionSource"
| union (
    TimelineStats 
    | extend DetectionSource = "Timeline", AlertCount = HourlyAlerts, UniqueAttackTechniques = 0
    | extend AnalysisType = "Timeline"
)
```

## 3. Advanced CASE Statements

```kql
// Categorize alerts and incidents with complex business logic
AlertInfo
| join kind=leftouter (
    SecurityIncident
    | project TenantId, IncidentStatus = Status, IncidentSeverity = Severity, IncidentNumber, CreatedTime
) on TenantId
| extend 
    AlertPriority = case(
        Severity == "Critical" and Category == "Malware", "P0-Critical",
        Severity == "Critical" and Category != "Malware", "P1-High", 
        Severity == "High" and DetectionSource == "Microsoft Defender ATP", "P1-High",
        Severity == "High", "P2-Medium",
        Severity == "Medium" and AttackTechniques contains "T1055", "P2-Medium",
        Severity == "Medium", "P3-Low",
        "P4-Info"
    ),
    ResponseAction = case(
        Severity == "Critical", "Immediate escalation required",
        Severity == "High" and Category == "Malware", "Isolate endpoint within 1 hour",
        Severity == "High" and Category == "Suspicious Activity", "Investigate within 4 hours",
        Severity == "Medium" and isnotempty(IncidentNumber), "Follow incident workflow",
        "Standard monitoring"
    ),
    AlertAge = case(
        datetime_diff('hour', now(), Timestamp) <= 1, "Fresh",
        datetime_diff('hour', now(), Timestamp) <= 24, "Recent", 
        datetime_diff('day', now(), Timestamp) <= 7, "Week Old",
        "Stale"
    )
```

## 4. IF Functions with Conditional Logic

```kql
// Security metrics with conditional calculations
SecurityIncident
| join kind=leftouter (
    AlertInfo
    | summarize 
        TotalAlerts = count(),
        CriticalAlerts = countif(Severity == "Critical"),
        HighAlerts = countif(Severity == "High")
    by TenantId
) on TenantId
| extend
    // Conditional fields using if()
    IsHighPriority = if(Severity in ("High", "Critical"), true, false),
    ResolutionTime = if(isnotempty(ClosedTime), 
        datetime_diff('hour', ClosedTime, CreatedTime), 
        datetime_diff('hour', now(), CreatedTime)),
    SLABreach = if(Severity == "Critical" and datetime_diff('hour', now(), CreatedTime) > 4, 
        "SLA Breached", 
        if(Severity == "High" and datetime_diff('hour', now(), CreatedTime) > 24, 
            "SLA Breached", 
            "Within SLA")),
    AlertDensity = if(TotalAlerts > 0, 
        round(todouble(CriticalAlerts + HighAlerts) / todouble(TotalAlerts) * 100, 2), 
        0.0),
    EscalationRequired = if(Status == "New" and Severity == "Critical" and 
        datetime_diff('hour', now(), CreatedTime) > 2, true, false)
```

## 5. DCOUNT for Unique Analysis

```kql
// Comprehensive security metrics using dcount
AlertInfo
| join kind=leftouter (
    SecurityIncident
    | project TenantId, IncidentNumber, Status, CreatedTime, IncidentSeverity = Severity
) on TenantId
| where TimeGenerated > ago(30d)
| summarize
    // Basic counts
    TotalAlerts = count(),
    TotalIncidents = dcount(IncidentNumber),
    
    // Unique analysis using dcount
    UniqueTenants = dcount(TenantId),
    UniqueDetectionSources = dcount(DetectionSource),
    UniqueAttackTechniques = dcount(AttackTechniques),
    UniqueServiceSources = dcount(ServiceSource),
    UniqueAlertTitles = dcount(Title),
    
    // Severity distribution
    CriticalAlerts = countif(Severity == "Critical"),
    HighAlerts = countif(Severity == "High"),
    MediumAlerts = countif(Severity == "Medium"),
    
    // Time-based metrics
    FirstAlert = min(Timestamp),
    LastAlert = max(Timestamp),
    
    // Calculate unique techniques per severity
    CriticalTechniques = dcountif(AttackTechniques, Severity == "Critical"),
    HighTechniques = dcountif(AttackTechniques, Severity == "High")
    
by bin(TimeGenerated, 1d), Category
| extend
    AlertsPerTenant = round(todouble(TotalAlerts) / todouble(UniqueTenants), 2),
    TechniquesDiversity = round(todouble(UniqueAttackTechniques) / todouble(TotalAlerts) * 100, 2),
    IncidentToAlertRatio = if(TotalAlerts > 0, 
        round(todouble(TotalIncidents) / todouble(TotalAlerts) * 100, 2), 
        0.0)
```

## 6. Complex Multi-Table Analysis with All Functions

```kql
// Comprehensive security posture analysis
let SecurityMetrics = materialize(
    AlertInfo
    | where TimeGenerated > ago(7d)
    | join kind=leftouter (
        SecurityIncident
        | where TimeGenerated > ago(7d)
        | project 
            TenantId, 
            IncidentNumber, 
            IncidentStatus = Status, 
            IncidentSeverity = Severity,
            IncidentCreated = CreatedTime,
            IncidentClosed = ClosedTime,
            Classification
    ) on TenantId
    | extend
        // Complex case logic for risk scoring
        RiskScore = case(
            Severity == "Critical" and Category == "Malware", 100,
            Severity == "Critical", 90,
            Severity == "High" and AttackTechniques contains "T1055", 85,
            Severity == "High" and Category == "Data Exfiltration", 80,
            Severity == "High", 75,
            Severity == "Medium" and isnotempty(IncidentNumber), 60,
            Severity == "Medium", 45,
            30
        ),
        
        // Conditional processing with if
        IsEscalated = if(isnotempty(IncidentNumber), true, false),
        ResponseTime = if(isnotempty(IncidentClosed) and isnotempty(IncidentCreated),
            datetime_diff('hour', IncidentClosed, IncidentCreated),
            if(isnotempty(IncidentCreated), 
                datetime_diff('hour', now(), IncidentCreated), 
                int(null))),
        
        ThreatCategory = case(
            AttackTechniques contains "T1055" or AttackTechniques contains "T1027", "Process Injection/Defense Evasion",
            AttackTechniques contains "T1078", "Valid Accounts",
            AttackTechniques contains "T1071", "Application Layer Protocol", 
            Category == "Malware", "Malware Activity",
            Category == "Suspicious Activity", "Anomalous Behavior",
            "Other"
        )
);

// Final analysis with aggregations
SecurityMetrics
| summarize
    // Volume metrics
    TotalAlerts = count(),
    EscalatedAlerts = countif(IsEscalated),
    
    // Diversity metrics using dcount
    UniqueTenants = dcount(TenantId),
    UniqueThreatCategories = dcount(ThreatCategory),
    UniqueAttackTechniques = dcount(AttackTechniques),
    UniqueDetectionSources = dcount(DetectionSource),
    
    // Risk metrics
    AverageRiskScore = avg(RiskScore),
    MaxRiskScore = max(RiskScore),
    HighRiskAlerts = countif(RiskScore >= 80),
    
    // Response metrics
    AverageResponseTime = avgif(ResponseTime, isnotempty(ResponseTime)),
    FastestResponse = minif(ResponseTime, isnotempty(ResponseTime)),
    SlowestResponse = maxif(ResponseTime, isnotempty(ResponseTime)),
    
    // Time distribution
    PeakHour = arg_max(count(), bin(Timestamp, 1h)),
    
    // Classification metrics
    TruePositives = dcountif(IncidentNumber, Classification == "TruePositive"),
    FalsePositives = dcountif(IncidentNumber, Classification == "FalsePositive")
    
by TenantId, ThreatCategory
| extend
    EscalationRate = round(todouble(EscalatedAlerts) / todouble(TotalAlerts) * 100, 2),
    ThreatDiversity = round(todouble(UniqueAttackTechniques) / todouble(TotalAlerts) * 100, 2),
    RiskLevel = case(
        AverageRiskScore >= 85, "Critical Risk",
        AverageRiskScore >= 70, "High Risk", 
        AverageRiskScore >= 50, "Medium Risk",
        "Low Risk"
    )
| order by AverageRiskScore desc, TotalAlerts desc
```

## 7. Time-Series Analysis with Window Functions

```kql
// Trending analysis with sophisticated time windowing
AlertInfo
| where TimeGenerated > ago(30d)
| join kind=leftouter (
    SecurityIncident
    | project TenantId, IncidentNumber, IncidentStatus = Status, CreatedTime
) on TenantId
| extend TimeWindow = bin(Timestamp, 6h)
| summarize
    AlertCount = count(),
    IncidentCount = dcount(IncidentNumber),
    CriticalCount = countif(Severity == "Critical"),
    UniqueTargets = dcount(MachineGroup),
    DiversityIndex = dcount(AttackTechniques)
by TimeWindow, TenantId
| extend
    // Calculate trends using prev() function
    AlertTrend = case(
        AlertCount > prev(AlertCount, 1), "Increasing",
        AlertCount < prev(AlertCount, 1), "Decreasing", 
        "Stable"
    ),
    
    // Risk assessment with complex conditions
    WindowRiskLevel = case(
        CriticalCount >= 5 and DiversityIndex >= 3, "Critical",
        CriticalCount >= 3 or (AlertCount >= 20 and DiversityIndex >= 2), "High",
        AlertCount >= 10 or IncidentCount >= 2, "Medium",
        "Low"
    ),
    
    // Calculate efficiency metrics
    IncidentRatio = if(AlertCount > 0, 
        round(todouble(IncidentCount) / todouble(AlertCount) * 100, 2), 
        0.0)
```

These queries demonstrate practical security operations scenarios and showcase the power of combining KQL functions for comprehensive analysis.
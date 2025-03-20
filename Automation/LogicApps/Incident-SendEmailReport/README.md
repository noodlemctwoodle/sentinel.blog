# Sentinel Incident Email Template

## Overview

This HTML template is designed for use with Azure Logic Apps to create formatted email notifications for Microsoft Sentinel incidents. The template provides a professional, consistent format for security incident reports sent to stakeholders.

## Features

- Clean, responsive HTML email design
- Customisable header with company logo
- Formatted sections for incident details and tactics
- Dynamic insertion points for entity and alert tables
- Professional footer with security team contact information
- Fully parameterised for easy customisation

## Usage

This template is designed to be used in the "Compose Email Response" action of an Azure Logic App workflow. It works in conjunction with the "Create HTML Table" actions for entities and alerts.

### Required Parameters

The template uses the following Logic App parameters:

- `emailLogoHeader`: URL for your company logo image
- `reportName`: Title for the report (e.g., "Sentinel Security Ops")
- `dateTimeFormat`: Format string for date/time display (e.g., "dd-MM-yyyy HH:mm:ss")
- `SecOpsEmail`: Contact email address for your security team

### Logic App Integration

In your Logic App's "Compose Email Response" action, paste this entire HTML code. The template will reference outputs from previous actions:

- `body('Create_HTML_table_with_Entities')`: HTML table of entities from the incident
- `body('Create_HTML_table_with_Alerts')`: HTML table of alerts from the incident

## Customisation

### Styling

The template includes CSS styling in the `<head>` section that can be modified to match your organisation's brand colours and styling preferences:

- Change the colour values to match your brand
- Adjust font sizes and spacing
- Modify table styles for entities and alerts

### Structure

The email is structured with the following sections:

1. Header with logo
2. Incident details (date, link, description, tactics)
3. Entities table
4. Alerts table
5. Footer with contact information

## Full Implementation Guide

For a complete guide on implementing this template as part of a Microsoft Sentinel incident reporting system, please visit our detailed blog post:

[Sentinel Alerts to Actionable Insights: Streamlining Security Incident Communication with Power-Packed Logic Apps](https://sentinel.blog/incident-reporting-logic-app)

## Licence

This template is provided under the MIT Licence. You are free to use, modify, and distribute it for your organisation's needs.

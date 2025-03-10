# Expiring Entra ID App Registrations Notification

This project provides an automated solution to monitor EntraID App Registrations for expiring credentials (both secrets and certificates) and send an email notification via a Logic App. The solution leverages an Azure Automation runbook that connects to Microsoft Graph using a system-assigned managed identity, retrieves applications and their credentials, and then posts a flat JSON payload to a Logic App endpoint. The Logic App, in turn, uses an email template to alert stakeholders of upcoming expirations.

## Features

- **Credential Monitoring:** Checks both password credentials (secrets) and key credentials (certificates) for each Azure AD App Registration.
- **Expiry Threshold:** Configurable threshold (default is 15 days) to identify credentials that are nearing expiration.
- **JSON Output:** Outputs expiring credential details in a flat JSON format with a custom date format (`dd-MM-yyyy HH:mm:ss`).
- **Logic App Integration:** Sends the JSON payload to a Logic App via an HTTP POST. The Logic App uses the incoming payload (via the `When_a_HTTP_request_is_received` trigger) to generate an email notification.
- **Email Notification:** An HTML email template (provided in the project) that displays a clear table of expiring credentials.

## Prerequisites

- **Azure Subscription:** Access to Azure to deploy the Automation Account and Logic App.
- **Azure AD Permissions:** The system-assigned managed identity of the Automation Account must have the necessary Microsoft Graph permissions (e.g., `Application.Read.All`).
- **Automation Account Modules:** Ensure that the required Microsoft Graph PowerShell modules (such as `Microsoft.Graph`) are imported into your Automation Account.
- **Logic App Setup:** A Logic App configured with a **When an HTTP request is received** trigger and email actions (using the provided HTML email template) to process and send notifications.

## Architecture

1. **Azure Automation Runbook:**  
   - Connects to Microsoft Graph using a system-assigned managed identity.
   - Retrieves all Azure AD App Registrations.
   - Checks for secrets and certificates that are set to expire within the defined threshold.
   - Formats the `ExpiryDate` to `dd-MM-yyyy HH:mm:ss` and creates a flat JSON payload.
   - Posts the JSON payload to a Logic App endpoint via an HTTP POST request.

2. **Logic App:**  
   - Receives the JSON payload via a **When an HTTP request is received** trigger.
   - Uses the payload data (referenced as `@{body('When_a_HTTP_request_is_received')}`) to populate the email template.
   - Sends an email notification to the designated recipients.

3. **Email Template:**  
   - An HTML email template with custom CSS to display the details in a readable table.
   - Ensures columns (such as ApplicationId and ExpiryDate) are not wrapped or squashed.

## Setup & Deployment

### 1. Import the Runbook Script
- In your Azure Automation Account, create a new PowerShell runbook.
- Paste the provided runbook script into the editor.
- Save and publish the runbook.

### 2. Import Required Modules
- Ensure that the **Microsoft.Graph.Authentication** and **Microsoft.Graph.Applications** PowerShell modules are imported into your Automation Account.
- Verify that the Automation Account is running on a compatible PowerShell runtime (PowerShell 7.2 is recommended).

### 3. Configure Managed Identity
- Enable the system-assigned managed identity on your Automation Account.
- Assign the necessary Microsoft Graph permissions (e.g., `Application.Read.All`) to the managed identity.

### 4. Setup the Logic App
- Create a new Logic App with a **When an HTTP request is received** trigger.
- Use the provided JSON schema and email template to process incoming data.
- Configure an email action to send notifications (e.g., via Office 365 Outlook, SMTP, etc.).

![Logic App Design](https://github.com/user-attachments/assets/8a37640f-b710-4d76-9fda-de4b847b3f92)

![Email Template](https://github.com/user-attachments/assets/489e5c14-1e9e-4cca-8aaf-4d20868124aa)

### 5. Configure Parameters
- The runbook script accepts parameters for `ExpiryThreshold` and `LogicAppUrl`. Adjust these parameters according to your needs.
- For example:  
  ```powershell
  -ExpiryThreshold 15 -LogicAppUrl "https://<your-logicapp-url>"

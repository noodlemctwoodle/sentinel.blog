# Azure Function Non-Approved Local Admins Report

This function runs a query and captures where non-approved local admins are logging onto a machine. This then exports the data to a JSON file and uploads it to a storage account.
The Storage Account is then called by a logic app that sends an email to Tenant owners.

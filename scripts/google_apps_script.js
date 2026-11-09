/**
 * ============================================================================
 * SurveilGuard AI - Google Apps Script Email Dispatch Web App
 * ============================================================================
 * 
 * SETUP INSTRUCTIONS:
 * 1. Open Google Apps Script: https://script.google.com
 * 2. Create a new project named "SurveilGuard-Email-Alerts"
 * 3. Paste this code into "Code.gs"
 * 4. Configure Project Settings > Script Properties:
 *      - WEBHOOK_SECRET: (e.g. "whsec_surveilguard_2026_super_secret_key")
 *      - ADMIN_EMAILS: (comma-separated list of 5 administrator emails)
 * 5. Deploy as Web App:
 *      - Click "Deploy" > "New deployment"
 *      - Select type: "Web app"
 *      - Description: "SurveilGuard AI Live Email Notifications"
 *      - Execute as: "Me" (your Google account)
 *      - Who has access: "Anyone"
 * 6. Copy the resulting "Web app URL" (ending with "/exec")
 * 7. In your SurveilGuard AI .env file:
 *      EMAIL_ENABLED=true
 *      EMAIL_PROVIDER=apps_script
 *      APPS_SCRIPT_WEB_APP_URL=https://script.google.com/macros/s/YOUR_DEPLOYMENT_ID/exec
 *      APPS_SCRIPT_WEBHOOK_SECRET=your_webhook_secret_here
 * ============================================================================
 */

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Missing POST request body"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    var data;
    try {
      data = JSON.parse(e.postData.contents);
    } catch (parseError) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Invalid JSON format"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Retrieve script properties
    var props = PropertiesService.getScriptProperties();
    var expectedSecret = props.getProperty("WEBHOOK_SECRET");
    var configuredAdminEmails = props.getProperty("ADMIN_EMAILS") || "";

    if (!expectedSecret) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "WEBHOOK_SECRET property not set in Apps Script configuration"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Authenticate token against shared secret
    if (!data.token || data.token !== expectedSecret) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "Unauthorized: Invalid or missing token"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Extract payload fields
    var subject = data.subject || "Suspicious Activity Detected";
    var camera = data.camera || "CAM-01";
    var eventName = data.event || "Unauthorized Access";
    var timestamp = data.timestamp || new Date().toISOString();
    var details = data.details || "Suspicious activity detected by the surveillance system";

    // Build authorized admin email list from script property
    var authorizedAdmins = configuredAdminEmails.split(",").map(function(item) {
      return item.trim().toLowerCase();
    }).filter(function(item) {
      return item.length > 0 && item.indexOf("@") !== -1;
    });

    // Recipient determination:
    // Supports dynamic recipient if supplied; otherwise defaults to all 5 administrators
    var recipients = [];

    if (data.recipient && typeof data.recipient === "string") {
      var candidate = data.recipient.trim().toLowerCase();
      if (candidate && candidate.indexOf("@") !== -1) {
        recipients.push(candidate);
      }
    } else if (data.recipients && Array.isArray(data.recipients)) {
      data.recipients.forEach(function(r) {
        var clean = (r || "").trim().toLowerCase();
        if (clean && clean.indexOf("@") !== -1 && recipients.indexOf(clean) === -1) {
          recipients.push(clean);
        }
      });
    }

    // Fall back to configured administrators if no specific recipient provided
    if (recipients.length === 0) {
      recipients = authorizedAdmins;
    }

    if (recipients.length === 0) {
      return ContentService.createTextOutput(JSON.stringify({
        status: "error",
        message: "No valid recipient email addresses configured"
      })).setMimeType(ContentService.MimeType.JSON);
    }

    // Build plain text & HTML bodies
    var bodyText = "SURVEILGUARD AI - SECURITY ALERT\n\n" +
      "Subject: " + subject + "\n" +
      "Camera: " + camera + "\n" +
      "Event: " + eventName + "\n" +
      "Timestamp: " + timestamp + "\n" +
      "Details: " + details + "\n\n" +
      "Automated alert from SurveilGuard AI via Gmail MailApp.";

    var htmlBody = data.html_body || (
      "<!DOCTYPE html><html><body style='font-family: Arial, sans-serif; padding: 20px; background: #f3f4f6;'>" +
      "<div style='background: #fff; padding: 24px; border-radius: 8px; border-left: 5px solid #ef4444; max-width: 600px; margin: 0 auto;'>" +
      "<h2 style='color: #dc2626; margin-top: 0;'>⚠️ " + subject + "</h2>" +
      "<p><strong>Camera:</strong> " + camera + "</p>" +
      "<p><strong>Event:</strong> " + eventName + "</p>" +
      "<p><strong>Detected At:</strong> " + timestamp + "</p>" +
      "<p><strong>Details:</strong> " + details + "</p>" +
      "<hr style='border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;'>" +
      "<p style='font-size: 12px; color: #6b7280;'>Automated security alert delivered via Google Apps Script MailApp.</p>" +
      "</div></body></html>"
    );

    // Send emails via MailApp
    var sentCount = 0;
    for (var i = 0; i < recipients.length; i++) {
      MailApp.sendEmail({
        to: recipients[i],
        subject: subject,
        body: bodyText,
        htmlBody: htmlBody
      });
      sentCount++;
    }

    return ContentService.createTextOutput(JSON.stringify({
      status: "success",
      message: "Email alert accepted for sending",
      recipient_count: sentCount,
      timestamp: new Date().toISOString()
    })).setMimeType(ContentService.MimeType.JSON);

  } catch (err) {
    return ContentService.createTextOutput(JSON.stringify({
      status: "error",
      message: err.toString()
    })).setMimeType(ContentService.MimeType.JSON);
  }
}


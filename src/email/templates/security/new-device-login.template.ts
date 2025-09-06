import {
  EmailTemplate,
  NewDeviceLoginData,
} from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

export function generateNewDeviceLogin(
  data: NewDeviceLoginData,
): EmailTemplate {
  const subject = `🔐 New Device Login Alert - ${EMAIL_CONSTANTS.BRAND.NAME}`;

  const deviceDetails = [
    data.deviceInfo.browser && `Browser: ${data.deviceInfo.browser}`,
    data.deviceInfo.os && `Operating System: ${data.deviceInfo.os}`,
    data.deviceInfo.ip && `IP Address: ${data.deviceInfo.ip}`,
    data.deviceInfo.location && `Location: ${data.deviceInfo.location}`,
  ]
    .filter(Boolean)
    .join('<br>');

  const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="${EMAIL_CONSTANTS.TEMPLATES.ENCODING}">
    <meta name="viewport" content="${EMAIL_CONSTANTS.TEMPLATES.VIEWPORT}">
    <title>${subject}</title>
    <style>
        body { 
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
          line-height: 1.6; 
          color: #333; 
          max-width: 600px; 
          margin: 0 auto; 
          padding: 20px; 
        }
        .header { 
          background: linear-gradient(135deg, #FF9500 0%, #FF7A00 100%); 
          color: white; 
          padding: 30px; 
          text-align: center; 
          border-radius: 10px 10px 0 0; 
        }
        .content { 
          background: #f8f9fa; 
          padding: 30px; 
          border-radius: 0 0 10px 10px; 
        }
        .btn { 
          display: inline-block; 
          background: #dc3545; 
          color: white; 
          padding: 15px 30px; 
          text-decoration: none; 
          border-radius: 5px; 
          font-weight: bold; 
          margin: 20px 0; 
        }
        .info-box { 
          background: white; 
          padding: 20px; 
          margin: 20px 0; 
          border-radius: 8px; 
          border: 1px solid #dee2e6; 
        }
        .warning { 
          background: #fff3cd; 
          border: 1px solid #ffeaa7; 
          padding: 15px; 
          border-radius: 5px; 
          margin: 20px 0; 
        }
        .footer { 
          text-align: center; 
          margin-top: 30px; 
          color: #666; 
          font-size: 14px; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Security Alert</h1>
        <p>New device login detected</p>
    </div>
    
    <div class="content">
        <h2>Hello ${data.fullName}!</h2>
        
        <p>We detected a new login to your ${EMAIL_CONSTANTS.BRAND.NAME} account from a device or location we don't recognize.</p>
        
        <div class="info-box">
            <h3>📍 Login Details:</h3>
            <p><strong>Login Time:</strong> ${data.loginTime.toLocaleString()}</p>
            ${deviceDetails ? `<p><strong>Device Information:</strong><br>${deviceDetails}</p>` : ''}
        </div>
        
        <div class="warning">
            <strong>⚠️ Was this you?</strong> If you recognize this login, you can ignore this email.
        </div>
        
        <p><strong>If this wasn't you:</strong></p>
        <ol>
            <li>Change your password immediately</li>
            <li>Review your account activity</li>
            <li>Enable two-factor authentication</li>
            <li>Contact our support team</li>
        </ol>
        
        <div style="text-align: center;">
            <a href="${data.securityUrl}" class="btn">Secure My Account</a>
        </div>
        
        <h3>🛡️ Security Tips:</h3>
        <ul>
            <li>Use a strong, unique password</li>
            <li>Enable two-factor authentication</li>
            <li>Don't share your login credentials</li>
            <li>Always log out from public computers</li>
        </ul>
        
        <p>If you have any concerns, please contact us immediately at <a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a></p>
    </div>
    
    <div class="footer">
        <p>Stay secure,<br>The ${EMAIL_CONSTANTS.BRAND.NAME} Security Team</p>
        <p><a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a> | <a href="${EMAIL_CONSTANTS.BRAND.WEBSITE}">${EMAIL_CONSTANTS.BRAND.WEBSITE}</a></p>
    </div>
</body>
</html>`;

  const deviceDetailsText = [
    data.deviceInfo.browser && `Browser: ${data.deviceInfo.browser}`,
    data.deviceInfo.os && `Operating System: ${data.deviceInfo.os}`,
    data.deviceInfo.ip && `IP Address: ${data.deviceInfo.ip}`,
    data.deviceInfo.location && `Location: ${data.deviceInfo.location}`,
  ]
    .filter(Boolean)
    .join('\n');

  const text = `
Security Alert - New Device Login

Hello ${data.fullName}!

We detected a new login to your ${EMAIL_CONSTANTS.BRAND.NAME} account from a device or location we don't recognize.

Login Details:
Login Time: ${data.loginTime.toLocaleString()}
${deviceDetailsText}

Was this you? If you recognize this login, you can ignore this email.

If this wasn't you:
1. Change your password immediately
2. Review your account activity
3. Enable two-factor authentication
4. Contact our support team

Secure your account: ${data.securityUrl}

Security Tips:
- Use a strong, unique password
- Enable two-factor authentication
- Don't share your login credentials
- Always log out from public computers

If you have any concerns, contact us at: ${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}

Stay secure,
The ${EMAIL_CONSTANTS.BRAND.NAME} Security Team
  `;

  return { subject, html, text };
}

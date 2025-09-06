import {
  EmailTemplate,
  PasswordChangeConfirmationData,
} from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

export function generatePasswordChangeConfirmation(
  data: PasswordChangeConfirmationData,
): EmailTemplate {
  const subject = `✅ Password Changed Successfully - ${EMAIL_CONSTANTS.BRAND.NAME}`;

  const deviceDetails = [
    data.deviceInfo?.browser && `Browser: ${data.deviceInfo.browser}`,
    data.deviceInfo?.os && `Operating System: ${data.deviceInfo.os}`,
    data.deviceInfo?.ip && `IP Address: ${data.deviceInfo.ip}`,
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
          background: linear-gradient(135deg, #28a745 0%, #20c997 100%); 
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
        .success { 
          background: #d4edda; 
          border: 1px solid #c3e6cb; 
          padding: 15px; 
          border-radius: 5px; 
          margin: 20px 0; 
          color: #155724; 
        }
        .danger { 
          background: #f8d7da; 
          border: 1px solid #f5c6cb; 
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
        <h1>✅ Password Changed</h1>
        <p>Your password has been updated successfully</p>
    </div>
    
    <div class="content">
        <h2>Hello ${data.fullName}!</h2>
        
        <div class="success">
            <strong>✅ Success!</strong> Your ${EMAIL_CONSTANTS.BRAND.NAME} password has been changed successfully.
        </div>
        
        <div class="info-box">
            <h3>📍 Change Details:</h3>
            <p><strong>Change Time:</strong> ${(data.changeTime ?? new Date()).toLocaleString()}</p>
            ${deviceDetails ? `<p><strong>Device Information:</strong><br>${deviceDetails}</p>` : ''}
        </div>
        
        <div class="danger">
            <strong>🚨 Didn't make this change?</strong> If you didn't change your password, your account may be compromised. Please secure your account immediately.
        </div>
        
        <div style="text-align: center;">
            <a href="${data.securityUrl ?? '#'}" class="btn">Review Account Security</a>
        </div>
        
        <h3>🛡️ Next Steps to Keep Your Account Secure:</h3>
        <ul>
            <li>Make sure you're the only one who knows your new password</li>
            <li>Consider enabling two-factor authentication</li>
            <li>Review your recent account activity</li>
            <li>Update your password on any shared devices</li>
            <li>Log out of all devices if you suspect unauthorized access</li>
        </ul>
        
        <p>If you have any security concerns or need assistance, please contact our support team immediately at <a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a></p>
    </div>
    
    <div class="footer">
        <p>Stay secure,<br>The ${EMAIL_CONSTANTS.BRAND.NAME} Security Team</p>
        <p><a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a> | <a href="${EMAIL_CONSTANTS.BRAND.WEBSITE}">${EMAIL_CONSTANTS.BRAND.WEBSITE}</a></p>
    </div>
</body>
</html>`;

  const deviceDetailsText = [
    data.deviceInfo?.browser && `Browser: ${data.deviceInfo.browser}`,
    data.deviceInfo?.os && `Operating System: ${data.deviceInfo.os}`,
    data.deviceInfo?.ip && `IP Address: ${data.deviceInfo.ip}`,
  ]
    .filter(Boolean)
    .join('\n');

  const text = `
Password Changed Successfully

Hello ${data.fullName}!

Your ${EMAIL_CONSTANTS.BRAND.NAME} password has been changed successfully.

Change Details:
Change Time: ${(data.changeTime ?? new Date()).toLocaleString()}
${deviceDetailsText}

Didn't make this change? If you didn't change your password, your account may be compromised. Please secure your account immediately.

Review account security: ${data.securityUrl ?? '#'}

Next Steps to Keep Your Account Secure:
- Make sure you're the only one who knows your new password
- Consider enabling two-factor authentication
- Review your recent account activity
- Update your password on any shared devices
- Log out of all devices if you suspect unauthorized access

If you have concerns, contact us at: ${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}

Stay secure,
The ${EMAIL_CONSTANTS.BRAND.NAME} Security Team
  `;

  return { subject, html, text };
}

import {
  EmailTemplate,
  AccountLockedData,
} from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

export function generateAccountLocked(data: AccountLockedData): EmailTemplate {
  const subject = `🔒 Account Locked - ${EMAIL_CONSTANTS.BRAND.NAME} Security Alert`;

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
          background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); 
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
        <h1>🔒 Account Locked</h1>
        <p>Your account has been temporarily locked</p>
    </div>
    
    <div class="content">
        <h2>Hello ${data.fullName}!</h2>
        
        <div class="danger">
            <strong>🚨 Security Alert:</strong> Your ${EMAIL_CONSTANTS.BRAND.NAME} account has been locked for security reasons.
        </div>
        
        <p><strong>Lock Time:</strong> ${data.lockTime.toLocaleString()}</p>
        <p><strong>Reason:</strong> ${data.reason}</p>
        
        <p>This security measure helps protect your account from unauthorized access.</p>
        
        <h3>What to do next:</h3>
        <ol>
            <li>Wait for the lock period to expire (if temporary)</li>
            <li>Contact our support team for immediate assistance</li>
            <li>Review your account security settings once unlocked</li>
            <li>Change your password if you suspect compromise</li>
        </ol>
        
        <div style="text-align: center;">
            <a href="mailto:${data.supportEmail}" class="btn">Contact Support</a>
        </div>
        
        <p>If you have any questions or need immediate assistance, please don't hesitate to contact our support team.</p>
    </div>
    
    <div class="footer">
        <p>${EMAIL_CONSTANTS.BRAND.NAME} Security Team</p>
        <p><a href="mailto:${data.supportEmail}">${data.supportEmail}</a></p>
    </div>
</body>
</html>`;

  const text = `
Account Locked - Security Alert

Hello ${data.fullName}!

Your ${EMAIL_CONSTANTS.BRAND.NAME} account has been locked for security reasons.

Lock Time: ${data.lockTime.toLocaleString()}
Reason: ${data.reason}

This security measure helps protect your account from unauthorized access.

What to do next:
1. Wait for the lock period to expire (if temporary)
2. Contact our support team for immediate assistance
3. Review your account security settings once unlocked
4. Change your password if you suspect compromise

Contact Support: ${data.supportEmail}

${EMAIL_CONSTANTS.BRAND.NAME} Security Team
  `;

  return { subject, html, text };
}

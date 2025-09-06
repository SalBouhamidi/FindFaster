import {
  EmailTemplate,
  PasswordResetData,
} from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

export function generatePasswordReset(data: PasswordResetData): EmailTemplate {
  const subject = `🔑 Reset Your ${EMAIL_CONSTANTS.BRAND.NAME} Password`;

  const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="${EMAIL_CONSTANTS.TEMPLATES.ENCODING}">
    <meta name="viewport" content="${EMAIL_CONSTANTS.TEMPLATES.VIEWPORT}">
    <title>${subject}</title>
    <style>
        body { 
          line-height: 1.6; 
          color: #333; 
          max-width: 600px; 
          margin: 0 auto; 
          padding: 20px; 
        }
        .header { 
          background: linear-gradient(135deg, #ffd966 25%, #ffd966 100%); 
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
          background: linear-gradient(135deg, #ffd966 25%, #ffd557ff 75%); 
          color: black !important; 
          padding: 9px 30px;
          font-size: 1.25rem;
          font-weight: 900;
          border: 1px solid black;
          border-radius: 9px; 
          text-decoration: none !important; 
          box-shadow: 6px 6px 0px 0px rgba(0, 0, 0, 1);
          margin: 20px 0;
          transition: all 0.2s ease-in-out;
          text-align: center;
        }
        .btn:hover {
          background: #ffe699; /* lighter shade for hover */
        }
        .warning { 
          background: #fff3cd; 
          border: 1px solid #ffeaa7; 
          padding: 15px; 
          border-radius: 5px; 
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
        <h1>🔑 Password Reset Request</h1>
        <p>Reset your ${EMAIL_CONSTANTS.BRAND.NAME} password</p>
    </div>
    
    <div class="content">
        <h2>Hello ${data.fullName}!</h2>
        
        <p>We received a request to reset your ${EMAIL_CONSTANTS.BRAND.NAME} password. If you made this request, click the button below to set a new password.</p>
        
        <div style="text-align: center;">
            <a href="${data.resetUrl}" class="btn">Reset My Password</a>
        </div>
        
        <div class="warning">
            <strong>⏰ Important:</strong> This password reset link will expire in ${data.expiresInHours} hour(s) for security reasons.
        </div>
        
        <p>If the button above doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 5px;">${data.resetUrl}</p>
        
        <div class="danger">
            <strong>🚨 Didn't request this?</strong> If you didn't request a password reset, please ignore this email. Your account is still secure.
        </div>
        
        <h3>🛡️ Security Tips for Your New Password:</h3>
        <ul>
            <li>Use at least 8 characters</li>
            <li>Include uppercase and lowercase letters</li>
            <li>Add numbers and special characters</li>
            <li>Don't reuse old passwords</li>
            <li>Consider using a password manager</li>
        </ul>
        
        <p>If you continue to have trouble accessing your account, please contact our support team at <a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a></p>
    </div>
    
    <div class="footer">
        <p>Best regards,<br>The ${EMAIL_CONSTANTS.BRAND.NAME} Security Team</p>
        <p><a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a> | <a href="${EMAIL_CONSTANTS.BRAND.WEBSITE}">${EMAIL_CONSTANTS.BRAND.WEBSITE}</a></p>
    </div>
</body>
</html>`;

  const text = `
Password Reset Request

Hello ${data.fullName}!

We received a request to reset your ${EMAIL_CONSTANTS.BRAND.NAME} password. If you made this request, use the link below to set a new password:

${data.resetUrl}

This password reset link will expire in ${data.expiresInHours} hour(s) for security reasons.

Didn't request this? If you didn't request a password reset, please ignore this email. Your account is still secure.

Security Tips for Your New Password:
- Use at least 8 characters
- Include uppercase and lowercase letters
- Add numbers and special characters
- Don't reuse old passwords
- Consider using a password manager

If you need help, contact us at: ${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}

Best regards,
The ${EMAIL_CONSTANTS.BRAND.NAME} Security Team
  `;

  return { subject, html, text };
}

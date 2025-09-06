import {
  EmailTemplate,
  EmailVerificationData,
} from '@email/interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '@email/constants/email.constants';

export function generateEmailVerification(
  data: EmailVerificationData,
): EmailTemplate {
  const subject = `Verify Your ${EMAIL_CONSTANTS.BRAND.NAME} Email Address`;

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
        <h1>🚀 Welcome to ${EMAIL_CONSTANTS.BRAND.NAME}!</h1>
        <p>Please verify your email address to get started</p>
    </div>
    
    <div class="content">
        <h2>Hello ${data.fullName}!</h2>
        
        <p>Thank you for joining ${EMAIL_CONSTANTS.BRAND.NAME}. FindFaster helps you search smarter and find faster by running Google dorks instantly, so you can uncover hidden results and save time. Please verify your email to get started.</p>
        
        <div style="text-align: center;">
            <a href="${data.verificationUrl}" class="btn">Verify My Email Address</a>
        </div>
        
        <div class="warning">
            <strong>⏰ Important:</strong> This verification link will expire in ${data.expiresInHours} hours.
        </div>
        
        <p>If the button above doesn't work, copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background: #e9ecef; padding: 10px; border-radius: 5px;">${data.verificationUrl}</p>
        
        <p>Once verified, you'll be able to:</p>
        <ul>
          <li>⚡ Run Google dorks instantly</li>
          <li>🔍 Discover hidden search results</li>
          <li>🛠️ Save time with smarter queries</li>
          <li>🌐 Explore the web more efficiently</li>
        </ul>
        
        <p>If you didn't create this account, please ignore this email.</p>
    </div>
    
    <div class="footer">
        <p>Best regards,<br>The ${EMAIL_CONSTANTS.BRAND.NAME} Team</p>
        <p><a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a> | <a href="${EMAIL_CONSTANTS.BRAND.WEBSITE}">${EMAIL_CONSTANTS.BRAND.WEBSITE}</a></p>
    </div>
</body>
</html>`;

  const text = `
Welcome to ${EMAIL_CONSTANTS.BRAND.NAME}!

Hello ${data.fullName}!

Thank you for joining ${EMAIL_CONSTANTS.BRAND.NAME}. To complete your registration, please verify your email address by clicking the link below:

${data.verificationUrl}

This verification link will expire in ${data.expiresInHours} hours.

Once verified, you'll be able to  Run Google dorks instantly, Discover hidden search results, and much more.

If you didn't create this account, please ignore this email.

Best regards,
The ${EMAIL_CONSTANTS.BRAND.NAME} Team
${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}
  `;

  return { subject, html, text };
}

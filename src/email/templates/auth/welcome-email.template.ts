import {
  EmailTemplate,
  WelcomeEmailData,
} from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

export function generateWelcomeEmail(data: WelcomeEmailData): EmailTemplate {
  const subject = `Welcome to ${EMAIL_CONSTANTS.BRAND.NAME} - Your Trading Journey Starts Now! 🎉`;

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
          background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); 
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
          background: #4CAF50; 
          color: white; 
          padding: 15px 30px; 
          text-decoration: none; 
          border-radius: 5px; 
          font-weight: bold; 
          margin: 20px 0; 
        }
        .feature { 
          background: white; 
          padding: 20px; 
          margin: 15px 0; 
          border-radius: 8px; 
          border-left: 4px solid #4CAF50; 
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
        <h1>🎉 Welcome to ${EMAIL_CONSTANTS.BRAND.NAME}!</h1>
        <p>Your email has been verified successfully</p>
    </div>
    
    <div class="content">
        <h2>Hello ${data.fullName}!</h2>
        
        <p>Congratulations! Your ${EMAIL_CONSTANTS.BRAND.NAME} account is now active and ready to use. We're excited to help you take your trading to the next level.</p>
        
        <div style="text-align: center;">
            <a href="${data.dashboardUrl}" class="btn">Go to My Dashboard</a>
        </div>
        
        <h3>🚀 Get Started with These Features:</h3>
        
        <div class="feature">
            <h4>📊 Performance Analytics</h4>
            <p>Track your trading performance with detailed analytics and insights.</p>
        </div>
        
        <div class="feature">
            <h4>📈 Market Analysis</h4>
            <p>Access real-time market data and trend analysis tools.</p>
        </div>
        
        <div class="feature">
            <h4>🎯 Goal Setting</h4>
            <p>Set trading goals and monitor your progress with visual dashboards.</p>
        </div>
        
        <div class="feature">
            <h4>📱 Mobile Access</h4>
            <p>Take your trading analytics on the go with our mobile-optimized platform.</p>
        </div>
        
        <h3>Need Help?</h3>
        <p>Our support team is here to help you succeed:</p>
        <ul>
            <li>📧 Email us at <a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a></li>
            <li>📚 Check out our <a href="${data.supportUrl}">Help Center</a></li>
            <li>💬 Join our community forum</li>
        </ul>
        
        <p>Happy trading!</p>
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

Congratulations! Your ${EMAIL_CONSTANTS.BRAND.NAME} account is now active and ready to use. We're excited to help you take your trading to the next level.

Access your dashboard: ${data.dashboardUrl}

Get Started with These Features:
- Performance Analytics: Track your trading performance with detailed analytics
- Market Analysis: Access real-time market data and trend analysis tools
- Goal Setting: Set trading goals and monitor your progress
- Mobile Access: Take your analytics on the go

Need Help?
Email: ${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}
Help Center: ${data.supportUrl}

Happy trading!

Best regards,
The ${EMAIL_CONSTANTS.BRAND.NAME} Team
  `;

  return { subject, html, text };
}

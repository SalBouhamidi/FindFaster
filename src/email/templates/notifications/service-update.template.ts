import { EmailTemplate } from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

interface ServiceUpdateData {
  updateTitle: string;
  version: string;
  releaseDate: Date;
  newFeatures: string[];
  improvements: string[];
  bugFixes: string[];
  changelogUrl: string;
}

export function generateServiceUpdate(data: ServiceUpdateData): EmailTemplate {
  const subject = `🚀 Service Update: ${data.updateTitle} v${data.version} - ${EMAIL_CONSTANTS.BRAND.NAME}`;

  const featuresHtml = data.newFeatures
    .map((feature) => `<li>${feature}</li>`)
    .join('');
  const improvementsHtml = data.improvements
    .map((improvement) => `<li>${improvement}</li>`)
    .join('');
  const bugFixesHtml = data.bugFixes.map((fix) => `<li>${fix}</li>`).join('');

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
          background: #28a745; 
          color: white; 
          padding: 15px 30px; 
          text-decoration: none; 
          border-radius: 5px; 
          font-weight: bold; 
          margin: 20px 0; 
        }
        .update-section { 
          background: white; 
          padding: 20px; 
          margin: 15px 0; 
          border-radius: 8px; 
          border-left: 4px solid #28a745; 
        }
        .version-badge { 
          background: #28a745; 
          color: white; 
          padding: 5px 15px; 
          border-radius: 20px; 
          font-weight: bold; 
          display: inline-block; 
          margin: 10px 0; 
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
        <h1>🚀 Service Update</h1>
        <p>${data.updateTitle}</p>
        <div class="version-badge">v${data.version}</div>
    </div>
    
    <div class="content">
        <h2>What's New in ${EMAIL_CONSTANTS.BRAND.NAME}!</h2>
        
        <p>We're excited to announce the latest update to ${EMAIL_CONSTANTS.BRAND.NAME}, released on ${data.releaseDate.toLocaleDateString()}.</p>
        
        ${
          data.newFeatures.length > 0
            ? `
        <div class="update-section">
            <h3>✨ New Features:</h3>
            <ul>
                ${featuresHtml}
            </ul>
        </div>
        `
            : ''
        }
        
        ${
          data.improvements.length > 0
            ? `
        <div class="update-section">
            <h3>⚡ Improvements:</h3>
            <ul>
                ${improvementsHtml}
            </ul>
        </div>
        `
            : ''
        }
        
        ${
          data.bugFixes.length > 0
            ? `
        <div class="update-section">
            <h3>🐛 Bug Fixes:</h3>
            <ul>
                ${bugFixesHtml}
            </ul>
        </div>
        `
            : ''
        }
        
        <div style="text-align: center;">
            <a href="${data.changelogUrl}" class="btn">View Full Changelog</a>
        </div>
        
        <p>These updates are automatically available to all users. No action is required on your part.</p>
        
        <p>Thank you for using ${EMAIL_CONSTANTS.BRAND.NAME}. We're constantly working to improve your experience!</p>
    </div>
    
    <div class="footer">
        <p>Happy trading,<br>The ${EMAIL_CONSTANTS.BRAND.NAME} Development Team</p>
        <p><a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a></p>
    </div>
</body>
</html>`;

  const featuresText = data.newFeatures
    .map((feature) => `- ${feature}`)
    .join('\n');
  const improvementsText = data.improvements
    .map((improvement) => `- ${improvement}`)
    .join('\n');
  const bugFixesText = data.bugFixes.map((fix) => `- ${fix}`).join('\n');

  const text = `
Service Update: ${data.updateTitle} v${data.version}

What's New in ${EMAIL_CONSTANTS.BRAND.NAME}!

We're excited to announce the latest update to ${EMAIL_CONSTANTS.BRAND.NAME}, released on ${data.releaseDate.toLocaleDateString()}.

${
  data.newFeatures.length > 0
    ? `
New Features:
${featuresText}
`
    : ''
}

${
  data.improvements.length > 0
    ? `
Improvements:
${improvementsText}
`
    : ''
}

${
  data.bugFixes.length > 0
    ? `
Bug Fixes:
${bugFixesText}
`
    : ''
}

View Full Changelog: ${data.changelogUrl}

These updates are automatically available to all users. No action is required on your part.

Thank you for using ${EMAIL_CONSTANTS.BRAND.NAME}. We're constantly working to improve your experience!

Happy trading,
The ${EMAIL_CONSTANTS.BRAND.NAME} Development Team
  `;

  return { subject, html, text };
}

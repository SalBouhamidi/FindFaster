import { EmailTemplate } from '../../interfaces/email-template.interface';
import { EMAIL_CONSTANTS } from '../../constants/email.constants';

interface NewsletterData {
  title: string;
  articles: Array<{
    title: string;
    summary: string;
    url: string;
    imageUrl?: string;
  }>;
  month: string;
  unsubscribeUrl: string;
}

export function generateNewsletter(data: NewsletterData): EmailTemplate {
  const subject = `📰 ${data.title} - ${data.month} Newsletter`;

  const articlesHtml = data.articles
    .map(
      (article) => `
    <div class="article">
      ${article.imageUrl ? `<img src="${article.imageUrl}" alt="${article.title}" style="width: 100%; height: 200px; object-fit: cover; border-radius: 8px; margin-bottom: 15px;">` : ''}
      <h4><a href="${article.url}" style="color: #667eea; text-decoration: none;">${article.title}</a></h4>
      <p>${article.summary}</p>
      <a href="${article.url}" style="color: #667eea; font-weight: bold;">Read More →</a>
    </div>
  `,
    )
    .join('');

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
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
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
        .article { 
          background: white; 
          padding: 20px; 
          margin: 20px 0; 
          border-radius: 8px; 
          border: 1px solid #dee2e6; 
        }
        .footer { 
          text-align: center; 
          margin-top: 30px; 
          color: #666; 
          font-size: 14px; 
        }
        .unsubscribe { 
          margin-top: 20px; 
          font-size: 12px; 
          color: #999; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📰 ${data.title}</h1>
        <p>${data.month} Newsletter</p>
    </div>
    
    <div class="content">
        <h2>Hello from the ${EMAIL_CONSTANTS.BRAND.NAME} team!</h2>
        
        <p>Here are the latest updates and insights from our platform:</p>
        
        ${articlesHtml}
        
        <p>Thank you for being part of the ${EMAIL_CONSTANTS.BRAND.NAME} community!</p>
    </div>
    
    <div class="footer">
        <p>Best regards,<br>The ${EMAIL_CONSTANTS.BRAND.NAME} Team</p>
        <p><a href="mailto:${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}">${EMAIL_CONSTANTS.BRAND.SUPPORT_EMAIL}</a></p>
        
        <div class="unsubscribe">
            <p>Don't want to receive these emails? <a href="${data.unsubscribeUrl}">Unsubscribe here</a></p>
        </div>
    </div>
</body>
</html>`;

  const articlesText = data.articles
    .map(
      (article) => `
${article.title}
${article.summary}
Read more: ${article.url}
  `,
    )
    .join('\n---\n');

  const text = `
${data.title} - ${data.month} Newsletter

Hello from the ${EMAIL_CONSTANTS.BRAND.NAME} team!

Here are the latest updates and insights from our platform:

${articlesText}

Thank you for being part of the ${EMAIL_CONSTANTS.BRAND.NAME} community!

Best regards,
The ${EMAIL_CONSTANTS.BRAND.NAME} Team

---
Don't want to receive these emails? Unsubscribe: ${data.unsubscribeUrl}
  `;

  return { subject, html, text };
}

import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { EmailTemplateRepository } from '@email/repositories/email-template.repository';
import {
  EmailVerificationData,
  WelcomeEmailData,
} from '@email/interfaces/email-template.interface';
import {
  SmtpConfig,
  EmailInfo,
  RateLimitConfig,
} from '@email/types/email.types';

// Interfaces moved to '@email/interfaces/email-template.interface' and '@email/types/email.types'

/**
 * Email service for sending various types of emails
 * Handles SMTP configuration, template rendering, and email delivery
 */
@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);
  private transporter: nodemailer.Transporter;
  private readonly fromAddress: string;
  private readonly fromName: string;

  constructor(
    private readonly configService: ConfigService,
    private readonly templateRepo: EmailTemplateRepository,
  ) {
    this.initializeTransporter();
    this.fromAddress = this.configService.get<string>(
      'email.templates.from.address',
    )!;
    this.fromName = this.configService.get<string>(
      'email.templates.from.name',
    )!;
  }

  /**
   * Initialize SMTP transporter
   */
  private initializeTransporter(): void {
    const smtpConfig = this.configService.get<SmtpConfig>('email.smtp');

    if (!smtpConfig?.auth?.user || !smtpConfig?.auth?.pass) {
      this.logger.warn(
        'SMTP credentials not configured. Email functionality will be disabled.',
      );
      return;
    }

    this.transporter = nodemailer.createTransport({
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.secure,
      auth: {
        user: smtpConfig.auth.user,
        pass: smtpConfig.auth.pass,
      },
    });

    // Verify SMTP connection
    this.transporter
      .verify()
      .then(() => {
        this.logger.log('SMTP connection established successfully');
      })
      .catch((error) => {
        this.logger.error('SMTP connection failed:', error);
      });
  }

  /**
   * Send an email
   */
  private async sendEmail(
    to: string,
    subject: string,
    html: string,
    text: string,
  ): Promise<void> {
    if (!this.transporter) {
      this.logger.warn(
        `Email not sent (SMTP not configured): ${subject} to ${to}`,
      );
      return;
    }

    try {
      const info = (await this.transporter.sendMail({
        from: `"${this.fromName}" <${this.fromAddress}>`,
        to,
        subject,
        html,
        text,
      })) as EmailInfo;

      this.logger.log(
        `Email sent successfully: ${subject} to ${to} (MessageId: ${info.messageId})`,
      );
    } catch (error) {
      this.logger.error(`Failed to send email to ${to}:`, error);
      throw new BadRequestException('Failed to send email');
    }
  }

  /**
   * Check rate limiting for user emails
   */
  private checkRateLimit(email: string): void {
    const rateLimitConfig =
      this.configService.get<RateLimitConfig>('email.rateLimiting');

    if (!rateLimitConfig?.enabled) {
      return;
    }

    // This is a simplified rate limiting check
    // In production, you might want to use Redis or a dedicated rate limiting service
    this.logger.debug(`Rate limiting check for ${email}`);
  }

  /**
   * Send email verification email
   */
  async sendEmailVerification(
    userId: string,
    email: string,
    fullName: string,
    verificationToken: string,
  ): Promise<void> {
    this.checkRateLimit(email);

    const baseUrl = this.configService.get<string>('email.templates.baseUrl');
    const expiresInHours = Math.floor(
      this.configService.get<number>('email.verification.expiresIn')! /
        (1000 * 60 * 60),
    );

    const verificationData: EmailVerificationData = {
      fullName,
      verificationUrl: `${baseUrl}/verify-email?token=${verificationToken}&email=${encodeURIComponent(email)}`,
      expiresInHours,
    };

    const template = await this.templateRepo.getEmailVerification({
      fullName: verificationData.fullName,
      verificationUrl: verificationData.verificationUrl,
      expiresInHours,
    });

    await this.sendEmail(email, template.subject, template.html, template.text);

    this.logger.log(`Email verification sent to ${email} for user ${userId}`);
  }

  /**
   * Send welcome email after successful registration/verification
   */
  async sendWelcomeEmail(email: string, fullName: string): Promise<void> {
    this.checkRateLimit(email);

    const baseUrl = this.configService.get<string>('email.templates.baseUrl');

    const welcomeData: WelcomeEmailData = {
      fullName,
      dashboardUrl: `${baseUrl}/dashboard`,
      supportUrl: `${baseUrl}/support`,
    };

    const template = await this.templateRepo.getWelcomeEmail({
      fullName: welcomeData.fullName,
      dashboardUrl: welcomeData.dashboardUrl,
      supportUrl: welcomeData.supportUrl,
    });

    await this.sendEmail(email, template.subject, template.html, template.text);

    this.logger.log(`Welcome email sent to ${email}`);
  }

  /**
   * Send new device login alert
   */
  async sendNewDeviceLoginAlert(
    email: string,
    fullName: string,
    deviceInfo: {
      browser?: string;
      os?: string;
      ip?: string;
      location?: string;
    },
    loginTime: Date = new Date(),
  ): Promise<void> {
    this.checkRateLimit(email);

    const baseUrl = this.configService.get<string>('email.templates.baseUrl');

    const alertData = {
      fullName,
      deviceInfo,
      loginTime,
      securityUrl: `${baseUrl}/security`,
    };

    const template = await this.templateRepo.getNewDeviceLogin({
      fullName: alertData.fullName,
      deviceInfo: alertData.deviceInfo,
      location:
        alertData.deviceInfo.location ||
        alertData.deviceInfo.ip ||
        'Unknown Location',
      loginTime: alertData.loginTime,
      securityUrl: alertData.securityUrl,
    });

    await this.sendEmail(email, template.subject, template.html, template.text);

    this.logger.log(`New device login alert sent to ${email}`);
  }

  /**
   * Send password reset email
   */
  async sendPasswordReset(
    email: string,
    fullName: string,
    resetToken: string,
  ): Promise<void> {
    this.checkRateLimit(email);

    const baseUrl = this.configService.get<string>('email.templates.baseUrl');
    const resetData = {
      fullName,
      resetUrl: `${baseUrl}/reset-password?token=${resetToken}&email=${encodeURIComponent(email)}`,
      expiresInHours: Math.floor(
        this.configService.get<number>('email.passwordReset.expiresIn')! /
          (1000 * 60 * 60),
      ),
    };

    const template = await this.templateRepo.getPasswordReset({
      fullName: resetData.fullName,
      resetUrl: resetData.resetUrl,
      expiresInHours: resetData.expiresInHours,
    });

    await this.sendEmail(email, template.subject, template.html, template.text);

    this.logger.log(`Password reset email sent to ${email}`);
  }

  /**
   * Send password change confirmation
   */
  async sendPasswordChangeConfirmation(
    email: string,
    fullName: string,
    deviceInfo: {
      browser?: string;
      os?: string;
      ip?: string;
    },
    _changeTime?: Date,
  ): Promise<void> {
    this.checkRateLimit(email);

    // const baseUrl = this.configService.get<string>('email.templates.baseUrl');
    void deviceInfo;
    void _changeTime;

    const template = await this.templateRepo.getPasswordChangeConfirmation({
      fullName,
    });

    await this.sendEmail(email, template.subject, template.html, template.text);

    this.logger.log(`Password change confirmation sent to ${email}`);
  }

  /**
   * Send account locked notification
   */
  async sendAccountLocked(
    email: string,
    fullName: string,
    reason: string,
    lockTime: Date = new Date(),
  ): Promise<void> {
    this.checkRateLimit(email);

    const supportEmail = this.configService.get<string>(
      'email.templates.support.address',
    );

    const subject = '🔒 Account Locked - FindFaster Security Alert';

    const html = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${subject}</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }
        .content { background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }
        .btn { display: inline-block; background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 20px 0; }
        .danger { background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; margin-top: 30px; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Account Locked</h1>
        <p>Your account has been temporarily locked</p>
    </div>
    
    <div class="content">
        <h2>Hello ${fullName}!</h2>
        
        <div class="danger">
            <strong>🚨 Security Alert:</strong> Your FindFaster account has been locked for security reasons.
        </div>
        
        <p><strong>Lock Time:</strong> ${lockTime.toLocaleString()}</p>
        <p><strong>Reason:</strong> ${reason}</p>
        
        <p>This security measure helps protect your account from unauthorized access.</p>
        
        <h3>What to do next:</h3>
        <ol>
            <li>Wait for the lock period to expire (if temporary)</li>
            <li>Contact our support team for immediate assistance</li>
            <li>Review your account security settings once unlocked</li>
            <li>Change your password if you suspect compromise</li>
        </ol>
        
        <div style="text-align: center;">
            <a href="mailto:${supportEmail}" class="btn">Contact Support</a>
        </div>
        
        <p>If you have any questions or need immediate assistance, please don't hesitate to contact our support team.</p>
    </div>
    
    <div class="footer">
        <p>FindFaster Security Team</p>
        <p><a href="mailto:${supportEmail}">${supportEmail}</a></p>
    </div>
</body>
</html>`;

    const text = `
Account Locked - Security Alert

Hello ${fullName}!

Your FindFaster account has been locked for security reasons.

Lock Time: ${lockTime.toLocaleString()}
Reason: ${reason}

This security measure helps protect your account from unauthorized access.

What to do next:
1. Wait for the lock period to expire (if temporary)
2. Contact our support team for immediate assistance
3. Review your account security settings once unlocked
4. Change your password if you suspect compromise

Contact Support: ${supportEmail}

FindFaster Security Team
`;

    await this.sendEmail(email, subject, html, text);

    this.logger.log(`Account locked notification sent to ${email}`);
  }

  /**
   * Test email configuration by sending a test email
   */
  async sendTestEmail(to: string): Promise<void> {
    const subject = 'Test Email - FindFaster Email System';
    const html = `
<h1>Email Test Successful!</h1>
<p>This is a test email to verify that the FindFaster email system is working correctly.</p>
<p>Timestamp: ${new Date().toISOString()}</p>
`;
    const text = `Email Test Successful! This is a test email to verify that the FindFaster email system is working correctly. Timestamp: ${new Date().toISOString()}`;

    await this.sendEmail(to, subject, html, text);
  }
}

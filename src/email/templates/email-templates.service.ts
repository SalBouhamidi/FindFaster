import { Injectable } from '@nestjs/common';
import { EmailTemplate } from '../interfaces/email-template.interface';
import { generateEmailVerification } from './auth/email-verification.template';
import { generateWelcomeEmail } from './auth/welcome-email.template';
import { generatePasswordReset } from './auth/password-reset.template';
import { generatePasswordChangeConfirmation } from './auth/password-change-confirmation.template';
import { generateNewDeviceLogin } from './security/new-device-login.template';
import { generateAccountLocked } from './security/account-locked.template';
import { generateNewsletter } from './notifications/newsletter.template';
import { generateServiceUpdate } from './notifications/service-update.template';

@Injectable()
export class EmailTemplates {
  async emailVerification(
    fullName: string,
    verificationUrl: string,
    expiresInHours: number,
  ): Promise<EmailTemplate> {
    return generateEmailVerification({
      fullName,
      verificationUrl,
      expiresInHours,
    });
  }

  async welcomeEmail(
    fullName: string,
    dashboardUrl: string,
    supportUrl: string,
  ): Promise<EmailTemplate> {
    return generateWelcomeEmail({
      fullName,
      dashboardUrl,
      supportUrl,
    });
  }

  async newDeviceLogin(
    fullName: string,
    deviceInfo: {
      browser?: string;
      os?: string;
      ip?: string;
      location?: string;
    },
    loginTime: Date,
    securityUrl: string,
  ): Promise<EmailTemplate> {
    return generateNewDeviceLogin({
      fullName,
      deviceInfo,
      location: deviceInfo.location || deviceInfo.ip || 'Unknown Location',
      loginTime,
      securityUrl,
    });
  }

  async passwordReset(
    fullName: string,
    resetUrl: string,
    expiresInHours: number,
  ): Promise<EmailTemplate> {
    return generatePasswordReset({
      fullName,
      resetUrl,
      expiresInHours,
    });
  }

  async passwordChangeConfirmation(
    fullName: string,
    deviceInfo?: {
      browser?: string;
      os?: string;
      ip?: string;
    },
    changeTime?: Date,
    securityUrl?: string,
  ): Promise<EmailTemplate> {
    return generatePasswordChangeConfirmation({
      fullName,
      deviceInfo,
      changeTime,
      securityUrl,
    });
  }

  async accountLocked(
    fullName: string,
    reason: string,
    lockTime: Date,
    supportEmail: string,
  ): Promise<EmailTemplate> {
    return generateAccountLocked({
      fullName,
      reason,
      lockTime,
      supportEmail,
    });
  }

  async newsletter(
    title: string,
    articles: Array<{
      title: string;
      summary: string;
      url: string;
      imageUrl?: string;
    }>,
    month: string,
    unsubscribeUrl: string,
  ): Promise<EmailTemplate> {
    return generateNewsletter({
      title,
      articles,
      month,
      unsubscribeUrl,
    });
  }

  async serviceUpdate(
    updateTitle: string,
    version: string,
    releaseDate: Date,
    newFeatures: string[],
    improvements: string[],
    bugFixes: string[],
    changelogUrl: string,
  ): Promise<EmailTemplate> {
    return generateServiceUpdate({
      updateTitle,
      version,
      releaseDate,
      newFeatures,
      improvements,
      bugFixes,
      changelogUrl,
    });
  }
}

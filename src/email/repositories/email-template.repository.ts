import { Injectable } from '@nestjs/common';
import {
  EmailTemplate,
  EmailVerificationData,
  WelcomeEmailData,
  NewDeviceLoginData,
  PasswordResetData,
  PasswordChangeConfirmationData,
} from '@email/interfaces/email-template.interface';
import { IEmailTemplateRepository } from '@email/interfaces/email-template-repository.interface';
import { EmailTemplates } from '@email/templates/email-templates.service';

@Injectable()
export class EmailTemplateRepository implements IEmailTemplateRepository {
  constructor(private readonly emailTemplates: EmailTemplates) {}

  async getEmailVerification(
    data: EmailVerificationData,
  ): Promise<EmailTemplate> {
    return this.emailTemplates.emailVerification(
      data.fullName,
      data.verificationUrl,
      data.expiresInHours,
    );
  }

  async getWelcomeEmail(data: WelcomeEmailData): Promise<EmailTemplate> {
    return this.emailTemplates.welcomeEmail(
      data.fullName,
      data.dashboardUrl,
      data.supportUrl,
    );
  }

  async getNewDeviceLogin(data: NewDeviceLoginData): Promise<EmailTemplate> {
    return this.emailTemplates.newDeviceLogin(
      data.fullName,
      data.deviceInfo,
      data.loginTime,
      data.securityUrl,
    );
  }

  async getPasswordReset(data: PasswordResetData): Promise<EmailTemplate> {
    return this.emailTemplates.passwordReset(
      data.fullName,
      data.resetUrl,
      data.expiresInHours,
    );
  }

  async getPasswordChangeConfirmation(
    data: PasswordChangeConfirmationData,
  ): Promise<EmailTemplate> {
    return this.emailTemplates.passwordChangeConfirmation(
      data.fullName,
      data.deviceInfo,
      data.changeTime,
      data.securityUrl,
    );
  }
}

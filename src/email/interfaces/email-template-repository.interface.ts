import {
  EmailTemplate,
  EmailVerificationData,
  WelcomeEmailData,
  NewDeviceLoginData,
  PasswordResetData,
  PasswordChangeConfirmationData,
} from './email-template.interface';

export interface IEmailTemplateRepository {
  getEmailVerification(
    data: EmailVerificationData,
  ): Promise<EmailTemplate> | EmailTemplate;

  getWelcomeEmail(
    data: WelcomeEmailData,
  ): Promise<EmailTemplate> | EmailTemplate;

  getNewDeviceLogin(
    data: NewDeviceLoginData,
  ): Promise<EmailTemplate> | EmailTemplate;

  getPasswordReset(
    data: PasswordResetData,
  ): Promise<EmailTemplate> | EmailTemplate;

  getPasswordChangeConfirmation(
    data: PasswordChangeConfirmationData,
  ): Promise<EmailTemplate> | EmailTemplate;
}

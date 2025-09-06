export interface EmailTemplate {
  subject: string;
  html: string;
  text: string;
}

export interface EmailVerificationData {
  fullName: string;
  verificationUrl: string;
  expiresInHours: number;
}

export interface WelcomeEmailData {
  fullName: string;
  dashboardUrl: string;
  supportUrl: string;
}

export interface NewDeviceLoginData {
  fullName: string;
  deviceInfo: {
    browser?: string;
    os?: string;
    ip?: string;
    location?: string;
  };
  location: string;
  loginTime: Date;
  securityUrl: string;
}

export interface PasswordResetData {
  fullName: string;
  resetUrl: string;
  expiresInHours: number;
}

export interface PasswordChangeConfirmationData {
  fullName: string;
  deviceInfo?: {
    browser?: string;
    os?: string;
    ip?: string;
  };
  changeTime?: Date;
  securityUrl?: string;
}

export interface AccountLockedData {
  fullName: string;
  reason: string;
  lockTime: Date;
  supportEmail: string;
}

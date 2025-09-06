export const EMAIL_CONSTANTS = {
  RATE_LIMIT: {
    DEFAULT_MAX_PER_HOUR: 10,
    DEFAULT_MAX_PER_DAY: 50,
  },
  EXPIRATION: {
    EMAIL_VERIFICATION_HOURS: 24,
    PASSWORD_RESET_HOURS: 1,
  },
  BRAND: {
    NAME: 'FindFaster',
    SUPPORT_EMAIL: 'bouhamidi.sal@gmail.com',
    WEBSITE: 'https://findfaster.io',
  },
  TEMPLATES: {
    ENCODING: 'utf-8',
    VIEWPORT: 'width=device-width, initial-scale=1.0',
  },
} as const;

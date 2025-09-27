import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';
import { isObject, isString, hasProperty } from '../utils/type-guards';

export interface PasswordPolicyOptions {
  minLength?: number;
  maxLength?: number;
  requireUppercase?: boolean;
  requireLowercase?: boolean;
  requireNumbers?: boolean;
  requireSpecialChars?: boolean;
  forbidCommonPasswords?: boolean;
  forbidPersonalInfo?: boolean;
  forbidSequential?: boolean;
  forbidRepeating?: boolean;
}

const DEFAULT_PASSWORD_POLICY: Required<PasswordPolicyOptions> = {
  minLength: 8,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  forbidCommonPasswords: true,
  forbidPersonalInfo: true,
  forbidSequential: true,
  forbidRepeating: true,
};

// Common weak passwords list (simplified for example)
const COMMON_PASSWORDS = [
  'password',
  '123456',
  '123456789',
  'qwerty',
  'abc123',
  'password123',
  'admin',
  'letmein',
  'welcome',
  'monkey',
  '1234567890',
  'dragon',
  'superman',
  'sunshine',
  'master',
  'football',
  'baseball',
  'batman',
  'trustno1',
  '111111',
  '000000',
  'login',
  'passw0rd',
  'test123',
];

@ValidatorConstraint({ name: 'isStrongPassword', async: false })
export class IsStrongPasswordConstraint
  implements ValidatorConstraintInterface
{
  validate(password: string, args: ValidationArguments): boolean {
    const options: PasswordPolicyOptions = isObject(args.constraints[0])
      ? (args.constraints[0] as PasswordPolicyOptions)
      : {};
    const policy = { ...DEFAULT_PASSWORD_POLICY, ...options };

    return this.validatePassword(password, policy, args.object).isValid;
  }

  defaultMessage(args: ValidationArguments): string {
    const options: PasswordPolicyOptions = isObject(args.constraints[0])
      ? (args.constraints[0] as PasswordPolicyOptions)
      : {};
    const policy = { ...DEFAULT_PASSWORD_POLICY, ...options };
    const validation = this.validatePassword(
      isString(args.value) ? args.value : '',
      policy,
      args.object,
    );

    return validation.errors.join(', ');
  }

  private validatePassword(
    password: string,
    policy: Required<PasswordPolicyOptions>,
    userInfo?: unknown,
  ): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!password) {
      errors.push('Password is required');
      return { isValid: false, errors };
    }

    // Length validation
    if (password.length < policy.minLength) {
      errors.push(
        `Password must be at least ${policy.minLength} characters long`,
      );
    }

    if (password.length > policy.maxLength) {
      errors.push(`Password must not exceed ${policy.maxLength} characters`);
    }

    // Character requirements
    if (policy.requireUppercase && !/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }

    if (policy.requireLowercase && !/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }

    if (policy.requireNumbers && !/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }

    if (
      policy.requireSpecialChars &&
      !/[!@#$%^&*(),.?":{}|<>]/.test(password)
    ) {
      errors.push(
        'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)',
      );
    }

    // Common password check
    if (policy.forbidCommonPasswords) {
      const lowercasePassword = password.toLowerCase();
      if (COMMON_PASSWORDS.includes(lowercasePassword)) {
        errors.push(
          'Password is too common, please choose a more secure password',
        );
      }
    }

    // Personal information check
    if (policy.forbidPersonalInfo && isObject(userInfo)) {
      const personalInfo: string[] = [];

      if (hasProperty(userInfo, 'fullName') && isString(userInfo.fullName)) {
        personalInfo.push(userInfo.fullName);
      }

      if (hasProperty(userInfo, 'email') && isString(userInfo.email)) {
        const emailPart = userInfo.email.split('@')[0];
        if (emailPart) personalInfo.push(emailPart);
      }

      if (hasProperty(userInfo, 'firstName') && isString(userInfo.firstName)) {
        personalInfo.push(userInfo.firstName);
      }

      if (hasProperty(userInfo, 'lastName') && isString(userInfo.lastName)) {
        personalInfo.push(userInfo.lastName);
      }

      for (const info of personalInfo) {
        if (password.toLowerCase().includes(info.toLowerCase())) {
          errors.push('Password should not contain personal information');
          break;
        }
      }
    }

    // Sequential characters check
    if (policy.forbidSequential) {
      if (this.hasSequentialChars(password)) {
        errors.push(
          'Password should not contain sequential characters (e.g., 123, abc)',
        );
      }
    }

    // Repeating characters check
    if (policy.forbidRepeating) {
      if (this.hasRepeatingChars(password)) {
        errors.push(
          'Password should not contain more than 2 repeating characters',
        );
      }
    }

    return { isValid: errors.length === 0, errors };
  }

  private hasSequentialChars(password: string): boolean {
    const sequences = [
      '0123456789',
      'abcdefghijklmnopqrstuvwxyz',
      'qwertyuiop',
      'asdfghjkl',
      'zxcvbnm',
      'azertyuiop',
      'qsdfghjklm',
      'wxcvbn',
    ];

    for (const sequence of sequences) {
      for (let i = 0; i <= sequence.length - 3; i++) {
        const subSeq = sequence.substring(i, i + 3);
        if (
          password.toLowerCase().includes(subSeq) ||
          password.toLowerCase().includes(subSeq.split('').reverse().join(''))
        ) {
          return true;
        }
      }
    }

    return false;
  }

  private hasRepeatingChars(password: string): boolean {
    for (let i = 0; i < password.length - 2; i++) {
      if (password[i] === password[i + 1] && password[i] === password[i + 2]) {
        return true;
      }
    }
    return false;
  }
}

/**
 * Strong password validation decorator
 * @param options Password policy options
 * @param validationOptions Class validator options
 */
export function IsStrongPassword(
  options?: PasswordPolicyOptions,
  validationOptions?: ValidationOptions,
) {
  return function (object: object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [options],
      validator: IsStrongPasswordConstraint,
    });
  };
}

/**
 * Password strength assessment utility
 */
export class PasswordStrengthChecker {
  static assessStrength(password: string): {
    score: number;
    level: 'very-weak' | 'weak' | 'medium' | 'strong' | 'very-strong';
    feedback: string[];
  } {
    let score = 0;
    const feedback: string[] = [];

    // Length scoring
    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (password.length >= 16) score += 1;

    // Character variety scoring
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;

    // Complexity bonus
    const uniqueChars = new Set(password).size;
    if (uniqueChars / password.length > 0.5) score += 1;

    // Penalty for common patterns
    if (/(.)\1{2,}/.test(password)) {
      score -= 1;
      feedback.push('Avoid repeating characters');
    }

    // Determine level
    let level: 'very-weak' | 'weak' | 'medium' | 'strong' | 'very-strong';
    if (score < 3) level = 'very-weak';
    else if (score < 5) level = 'weak';
    else if (score < 7) level = 'medium';
    else if (score < 9) level = 'strong';
    else level = 'very-strong';

    // Generate feedback
    if (password.length < 8) feedback.push('Use at least 8 characters');
    if (!/[a-z]/.test(password)) feedback.push('Add lowercase letters');
    if (!/[A-Z]/.test(password)) feedback.push('Add uppercase letters');
    if (!/\d/.test(password)) feedback.push('Add numbers');
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password))
      feedback.push('Add special characters');

    return { score: Math.max(0, score), level, feedback };
  }
}

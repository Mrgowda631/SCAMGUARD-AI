/**
 * Strong Password Security Policy Validator for SCAMGUARD AI SOC
 * Enforces enterprise-grade authentication standards:
 * - Minimum 8 characters, maximum 64 characters
 * - At least one uppercase letter (A-Z)
 * - At least one lowercase letter (a-z)
 * - At least one numeric digit (0-9)
 * - At least one special character / symbol (!@#$%^&* etc.)
 * - Explicitly rejects passwords consisting only of words/letters (e.g. "Sanjay Kumar")
 * - Explicitly rejects passwords consisting only of numbers (e.g. "12345678")
 * - Rejects trivial or easily guessable dictionary patterns
 */

export interface PasswordValidationOutput {
  valid: boolean;
  error?: string;
}

export function validateStrongPassword(password: string): PasswordValidationOutput {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required.' };
  }

  if (password.length < 8) {
    return { valid: false, error: 'Weak password rejected: Password must be at least 8 characters long.' };
  }

  if (password.length > 64) {
    return { valid: false, error: 'Weak password rejected: Password cannot exceed 64 characters.' };
  }

  // Reject passwords consisting only of words/letters and spaces (e.g. "Sanjay Kumar")
  if (/^[a-zA-Z\s]+$/.test(password)) {
    return {
      valid: false,
      error: 'Weak password rejected: Password cannot consist only of words or letters (e.g. "Sanjay Kumar"). It must include numbers (0-9) and special characters (!@#$%^&*).',
    };
  }

  // Reject passwords consisting only of numbers (e.g. "12345678")
  if (/^\d+$/.test(password)) {
    return {
      valid: false,
      error: 'Weak password rejected: Password cannot consist only of numbers. It must include alphabets (uppercase & lowercase) and special characters (!@#$%^&*).',
    };
  }

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[^a-zA-Z0-9]/.test(password);

  if (!hasUppercase) {
    return {
      valid: false,
      error: 'Weak password rejected: Must include at least one uppercase letter (A-Z).',
    };
  }

  if (!hasLowercase) {
    return {
      valid: false,
      error: 'Weak password rejected: Must include at least one lowercase letter (a-z).',
    };
  }

  if (!hasNumber) {
    return {
      valid: false,
      error: 'Weak password rejected: Must include at least one numeric digit (0-9).',
    };
  }

  if (!hasSpecial) {
    return {
      valid: false,
      error: 'Weak password rejected: Must include at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>? etc.).',
    };
  }

  // Common trivial passwords list
  const normalized = password.toLowerCase().replace(/\s+/g, '');
  const weakCommon = [
    'password123',
    'password@123',
    'admin123',
    'admin@123',
    'sanjaykumar',
    'sanjaykumar1',
    'qwertyuiop',
    '12345678',
  ];

  if (weakCommon.some(wp => normalized === wp || normalized === wp + '!')) {
    return {
      valid: false,
      error: 'Weak password rejected: This password is too common or easily guessable.',
    };
  }

  return { valid: true };
}


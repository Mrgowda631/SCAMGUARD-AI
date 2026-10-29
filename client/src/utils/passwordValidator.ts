/**
 * Strong Password Security Policy Evaluator for Frontend (SCAMGUARD AI)
 * Evaluates password strength in real time and enforces:
 * - 8+ characters
 * - Uppercase and lowercase alphabets
 * - Numbers (0-9)
 * - Special characters (!@#$%^&* etc.)
 * - Rejection of only words (e.g. "Sanjay Kumar") or only numbers
 */

export interface PasswordValidationResult {
  valid: boolean;
  score: number; // 0 to 4
  strengthLabel: 'Very Weak' | 'Weak' | 'Fair' | 'Strong';
  checks: {
    minLength: boolean;
    hasUppercase: boolean;
    hasLowercase: boolean;
    hasNumber: boolean;
    hasSpecial: boolean;
    notOnlyWords: boolean;
    notOnlyNumbers: boolean;
  };
  errors: string[];
}

export function evaluatePasswordStrength(password: string): PasswordValidationResult {
  const pwd = password || '';
  const minLength = pwd.length >= 8;
  const hasUppercase = /[A-Z]/.test(pwd);
  const hasLowercase = /[a-z]/.test(pwd);
  const hasNumber = /[0-9]/.test(pwd);
  const hasSpecial = /[^a-zA-Z0-9]/.test(pwd);
  const isOnlyWords = /^[a-zA-Z\s]+$/.test(pwd);
  const isOnlyNumbers = /^\d+$/.test(pwd);

  const errors: string[] = [];

  if (!minLength) {
    errors.push('At least 8 characters long');
  }
  if (!hasUppercase) {
    errors.push('At least one uppercase letter (A-Z)');
  }
  if (!hasLowercase) {
    errors.push('At least one lowercase letter (a-z)');
  }
  if (!hasNumber) {
    errors.push('At least one number (0-9)');
  }
  if (!hasSpecial) {
    errors.push('At least one special character (!@#$%^&* etc.)');
  }
  if (isOnlyWords && pwd.length > 0) {
    errors.push('Cannot consist only of words/letters (e.g. "Sanjay Kumar")');
  }
  if (isOnlyNumbers && pwd.length > 0) {
    errors.push('Cannot consist only of numbers');
  }

  let passedCriteria = 0;
  if (minLength) passedCriteria++;
  if (hasUppercase && hasLowercase) passedCriteria++;
  if (hasNumber) passedCriteria++;
  if (hasSpecial) passedCriteria++;
  if (!isOnlyWords && !isOnlyNumbers && pwd.length > 0) passedCriteria++;

  let strengthLabel: 'Very Weak' | 'Weak' | 'Fair' | 'Strong' = 'Very Weak';
  if (passedCriteria <= 2) strengthLabel = 'Very Weak';
  else if (passedCriteria === 3) strengthLabel = 'Weak';
  else if (passedCriteria === 4) strengthLabel = 'Fair';
  else if (passedCriteria === 5) strengthLabel = 'Strong';

  const valid =
    minLength &&
    hasUppercase &&
    hasLowercase &&
    hasNumber &&
    hasSpecial &&
    !isOnlyWords &&
    !isOnlyNumbers;

  return {
    valid,
    score: passedCriteria,
    strengthLabel,
    checks: {
      minLength,
      hasUppercase,
      hasLowercase,
      hasNumber,
      hasSpecial,
      notOnlyWords: !isOnlyWords,
      notOnlyNumbers: !isOnlyNumbers,
    },
    errors,
  };
}


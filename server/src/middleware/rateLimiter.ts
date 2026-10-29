import rateLimit from 'express-rate-limit';

// Rate limiter for authentication endpoints (prevent brute-force password guessing)
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 auth attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many authentication attempts from this IP. Please try again after 15 minutes.',
  },
});

// Rate limiter for scan/detect endpoints
export const detectRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // Limit each IP to 30 scam analyses per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Scan rate limit reached. Please wait a moment before submitting another scan.',
  },
});

// General API rate limiter
export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 300, // Limit each IP to 300 requests per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many API requests from this IP. Please slow down.',
  },
});

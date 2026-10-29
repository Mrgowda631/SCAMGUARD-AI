import { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { config } from '../config.js';

export function errorHandler(
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
): void {
  // Handle Zod Validation Errors
  if (err instanceof ZodError) {
    res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: err.errors.map(e => ({
        field: e.path.join('.'),
        message: e.message,
      })),
    });
    return;
  }

  // Handle Syntax Errors (e.g., malformed JSON payload)
  if (err instanceof SyntaxError && 'status' in err && (err as any).status === 400 && 'body' in err) {
    res.status(400).json({
      success: false,
      error: 'Malformed JSON payload in request body.',
    });
    return;
  }

  // Safe logging
  const safeMessage = err?.message || 'Unknown internal error';
  console.error('[Error Handler]', safeMessage);

  // Return clean, safe error response
  res.status(err.status || 500).json({
    success: false,
    error: config.isProd ? 'An internal server error occurred.' : safeMessage,
  });
}

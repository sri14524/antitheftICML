import validator from 'validator';

/**
 * Normalizes and validates incoming URL string.
 * Returns normalized URL object and hostname or throws ValidationError.
 */
export function sanitizeAndValidateUrl(inputUrl) {
  if (!inputUrl || typeof inputUrl !== 'string') {
    throw new Error('Please provide a valid URL string.');
  }

  let trimmed = inputUrl.trim();

  // If missing protocol, prepend https:// for evaluation
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = 'https://' + trimmed;
  }

  if (!validator.isURL(trimmed, {
    protocols: ['http', 'https'],
    require_protocol: true,
    require_valid_protocol: true,
    allow_underscores: true,
  })) {
    throw new Error('Invalid URL format. Please enter a valid web address or domain.');
  }

  const parsed = new URL(trimmed);

  return {
    normalizedUrl: parsed.toString(),
    origin: parsed.origin,
    hostname: parsed.hostname.toLowerCase(),
    protocol: parsed.protocol,
    pathname: parsed.pathname,
  };
}

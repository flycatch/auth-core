/**
 * Generates a standardized API response object.
 *
 * @param {number} code - HTTP status code or custom response code.
 * @param {string} message - Message describing the response.
 * @param {boolean} status - Indicates success (true) or failure (false).
 * @param {any[]} [data] - Optional array containing response data.
 * @returns {{
 *   timestamp: string,
 *   code: number,
 *   message: string,
 *   status: boolean,
 *   data?: any[]
 * }} Standardized API response object.
 */
export default (
  code: number,
  message: string,
  status: boolean,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data?: any[]
) => {
  return {
    timestamp: new Date().toISOString(),
    code,
    message,
    status,
    data,
  };
};

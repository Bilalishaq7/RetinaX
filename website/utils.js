/* ==========================================================================
   RetinaX — Clinical & Date Formatting Utilities (utils.js)
   ========================================================================== */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.RetinaXUtils = factory();
    // Also expose shorthand utils if not already defined
    if (!root.utils) {
      root.utils = root.RetinaXUtils;
    }
  }
}(typeof self !== 'undefined' ? self : this, function () {

  /**
   * Helper to parse any valid date input (Date object, timestamp number in sec/ms, ISO string) into a Date object.
   * Returns null if invalid.
   * @param {Date|number|string} input 
   * @returns {Date|null}
   */
  function parseDateInput(input) {
    if (input === null || input === undefined || input === '') {
      return null;
    }
    if (input instanceof Date) {
      return isNaN(input.getTime()) ? null : input;
    }
    if (typeof input === 'number') {
      // Soroban ledger timestamps are usually in seconds (e.g. 1786062300 < 10000000000)
      const ms = input < 10000000000 ? input * 1000 : input;
      const d = new Date(ms);
      return isNaN(d.getTime()) ? null : d;
    }
    if (typeof input === 'string') {
      // Check if numeric string
      if (!isNaN(input) && input.trim() !== '') {
        const num = Number(input);
        const ms = num < 10000000000 ? num * 1000 : num;
        const d = new Date(ms);
        return isNaN(d.getTime()) ? null : d;
      }
      const d = new Date(input);
      return isNaN(d.getTime()) ? null : d;
    }
    return null;
  }

  /**
   * Formats a date into a standard date string (YYYY-MM-DD or custom options).
   * @param {Date|number|string} dateInput 
   * @param {Object|string} [options] Format string 'YYYY-MM-DD' or Intl.DateTimeFormat options
   * @returns {string} Formatted date string, or 'Invalid Date' if invalid.
   */
  function formatDate(dateInput, options = 'YYYY-MM-DD') {
    const d = parseDateInput(dateInput);
    if (!d) return 'Invalid Date';

    if (options === 'YYYY-MM-DD') {
      const year = d.getUTCFullYear();
      const month = String(d.getUTCMonth() + 1).padStart(2, '0');
      const day = String(d.getUTCDate()).padStart(2, '0');
      return `${year}-${month}-${day}`;
    }

    if (options === 'MMM DD, YYYY') {
      const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
      const month = months[d.getUTCMonth()];
      const day = String(d.getUTCDate()).padStart(2, '0');
      const year = d.getUTCFullYear();
      return `${month} ${day}, ${year}`;
    }

    if (typeof options === 'object') {
      try {
        return new Intl.DateTimeFormat('en-US', options).format(d);
      } catch (e) {
        return 'Invalid Date';
      }
    }

    const year = d.getUTCFullYear();
    const month = String(d.getUTCMonth() + 1).padStart(2, '0');
    const day = String(d.getUTCDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  /**
   * Formats a Soroban/Unix timestamp into a human-readable UTC date/time string.
   * @param {number|string} timestamp Unix timestamp in seconds or milliseconds
   * @param {boolean} [includeTime=true] Whether to include HH:mm:ss UTC
   * @returns {string} Formatted timestamp string
   */
  function formatTimestamp(timestamp, includeTime = true) {
    const d = parseDateInput(timestamp);
    if (!d) return 'Invalid Date';

    const year = d.getUTCFullYear();
    const month = String(d.getUTCMonth() + 1).padStart(2, '0');
    const day = String(d.getUTCDate()).padStart(2, '0');
    const datePart = `${year}-${month}-${day}`;

    if (!includeTime) {
      return datePart;
    }

    const hours = String(d.getUTCHours()).padStart(2, '0');
    const minutes = String(d.getUTCMinutes()).padStart(2, '0');
    const seconds = String(d.getUTCSeconds()).padStart(2, '0');
    return `${datePart} ${hours}:${minutes}:${seconds} UTC`;
  }

  /**
   * Formats a date to ISO 8601 string for FHIR v4 compliance (e.g. 2026-08-06T23:45:00Z).
   * @param {Date|number|string} dateInput 
   * @returns {string} ISO 8601 timestamp string
   */
  function formatFHIRDate(dateInput) {
    const d = parseDateInput(dateInput);
    if (!d) return 'Invalid Date';
    return d.toISOString();
  }

  /**
   * Returns a relative time string (e.g., "5 minutes ago", "in 2 hours", "just now").
   * @param {Date|number|string} dateInput 
   * @param {Date|number|string} [referenceInput=Date.now()] Reference date for comparison
   * @returns {string} Relative time phrase
   */
  function formatRelativeTime(dateInput, referenceInput = Date.now()) {
    const d = parseDateInput(dateInput);
    const ref = parseDateInput(referenceInput);

    if (!d || !ref) return 'Invalid Date';

    const diffMs = d.getTime() - ref.getTime();
    const diffSec = Math.round(diffMs / 1000);
    const absSec = Math.abs(diffSec);

    if (absSec < 30) {
      return 'just now';
    }

    const minutes = Math.floor(absSec / 60);
    const hours = Math.floor(absSec / 3600);
    const days = Math.floor(absSec / 86400);

    let unitStr = '';
    if (days >= 1) {
      unitStr = days === 1 ? '1 day' : `${days} days`;
    } else if (hours >= 1) {
      unitStr = hours === 1 ? '1 hour' : `${hours} hours`;
    } else {
      unitStr = minutes === 1 ? '1 minute' : `${minutes} minutes`;
    }

    return diffSec > 0 ? `in ${unitStr}` : `${unitStr} ago`;
  }

  /**
   * Checks if an expiration timestamp (e.g. access grant TTL) has passed.
   * @param {number|string|Date} expiryInput Expiration timestamp
   * @param {number|string|Date} [currentInput=Date.now()] Reference timestamp
   * @returns {boolean} True if expired
   */
  function isExpired(expiryInput, currentInput = Date.now()) {
    const expiry = parseDateInput(expiryInput);
    const current = parseDateInput(currentInput);

    if (!expiry || !current) return true;

    return expiry.getTime() <= current.getTime();
  }

  /**
   * Formats a duration in seconds into a human-readable phrase (e.g. "24 Hours", "1 Hour 30 Mins").
   * @param {number} seconds 
   * @returns {string} Formatted duration string
   */
  function formatDuration(seconds) {
    if (typeof seconds !== 'number' || isNaN(seconds) || seconds < 0) {
      return '0 Mins';
    }

    const hours = Math.floor(seconds / 3600);
    const remainingSec = seconds % 3600;
    const minutes = Math.floor(remainingSec / 60);
    const secs = remainingSec % 60;

    const parts = [];
    if (hours > 0) {
      parts.push(hours === 1 ? '1 Hour' : `${hours} Hours`);
    }
    if (minutes > 0) {
      parts.push(minutes === 1 ? '1 Min' : `${minutes} Mins`);
    }
    if (parts.length === 0 && secs > 0) {
      parts.push(`${secs} Secs`);
    }

    return parts.length > 0 ? parts.join(' ') : '0 Mins';
  }

  /**
   * Truncates a Stellar/Soroban address for display in UI.
   * Shows first and last N characters with ellipsis in between.
   * @param {string} address Full Stellar address (typically 56 chars: G... or C...)
   * @param {number} [prefixLength=6] Number of characters to show at start
   * @param {number} [suffixLength=4] Number of characters to show at end
   * @returns {string} Truncated address (e.g., "GCZJM...XKP5" or "CDLZ...9B2A")
   */
  function truncateAddress(address, prefixLength = 6, suffixLength = 4) {
    if (typeof address !== 'string') {
      return '';
    }

    if (address.length === 0) {
      return '';
    }

    // If address is short enough, no truncation needed
    if (address.length <= prefixLength + suffixLength) {
      return address;
    }

    const prefix = address.substring(0, prefixLength);
    const suffix = address.substring(address.length - suffixLength);
    return `${prefix}...${suffix}`;
  }

  return {
    parseDateInput,
    formatDate,
    formatTimestamp,
    formatFHIRDate,
    formatRelativeTime,
    isExpired,
    formatDuration,
    truncateAddress
  };
}));

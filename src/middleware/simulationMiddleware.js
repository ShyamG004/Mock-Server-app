/**
 * Failure Simulation Middleware ("chaos" middleware)
 *
 * Forces backend failures so a client (e.g. the SIEM Connections module) can be
 * verified against timeouts, slow responses and hard error statuses.
 *
 * Two independent controls:
 *
 * 1. Global config - `simulation` block, set at runtime via POST /config
 *      { "simulation": { "mode": "none|timeout|error|delay", "delayMs": 0,
 *                        "errorStatus": 500, "errorMessage": "...",
 *                        "applyTo": ["/oauth2", "/oauth1"] } }
 *
 * 2. Per-request overrides - work even while `mode` is "none":
 *      ?_delay=<ms>          delay this single request
 *      ?_status=<400-599>    force this status on this single request
 *      x-mock-timeout: true  hang this single request
 *
 * Control endpoints (/config, /health, /ui, /api-docs) are NEVER simulated so
 * the server always stays reachable and recoverable.
 */

const configManager = require('../config/configManager');
const logger = require('../utils/logger');

// Never simulated - the server must stay controllable
const CONTROL_PATH_PREFIXES = ['/config', '/health', '/ui', '/api-docs'];

const MAX_DELAY_MS = 300000;
const MIN_ERROR_STATUS = 400;
const MAX_ERROR_STATUS = 599;

const VALID_SIMULATION_MODES = ['none', 'timeout', 'error', 'delay'];

const TRUTHY_HEADER_VALUES = ['true', '1', 'yes', 'on'];

/**
 * Prefix match on a path, treating the prefix as a path segment boundary
 * so `/configuration` is not matched by `/config`.
 */
function pathMatchesPrefix(path, prefix) {
  if (!prefix) return false;

  const normalizedPrefix = prefix.startsWith('/') ? prefix : `/${prefix}`;
  const trimmedPrefix = normalizedPrefix.length > 1 && normalizedPrefix.endsWith('/')
    ? normalizedPrefix.slice(0, -1)
    : normalizedPrefix;

  if (trimmedPrefix === '/') return true;
  if (path === trimmedPrefix) return true;

  return path.startsWith(`${trimmedPrefix}/`);
}

/**
 * Control paths are exempt from every form of simulation.
 */
function isControlPath(path) {
  return CONTROL_PATH_PREFIXES.some((prefix) => pathMatchesPrefix(path, prefix));
}

/**
 * An empty / missing applyTo list means "every non-control route".
 */
function isWithinApplyTo(path, applyTo) {
  if (!Array.isArray(applyTo) || applyTo.length === 0) return true;
  return applyTo.some((prefix) => pathMatchesPrefix(path, prefix));
}

function clampDelay(value) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) return 0;
  return Math.min(parsed, MAX_DELAY_MS);
}

/**
 * Read the effective simulation block, falling back to safe defaults.
 */
function getSimulationConfig() {
  const config = configManager.getConfig();
  const simulation = config && config.simulation ? config.simulation : {};

  return {
    mode: VALID_SIMULATION_MODES.includes(simulation.mode) ? simulation.mode : 'none',
    delayMs: clampDelay(simulation.delayMs),
    errorStatus: Number.isInteger(simulation.errorStatus) ? simulation.errorStatus : 500,
    errorMessage: typeof simulation.errorMessage === 'string' && simulation.errorMessage
      ? simulation.errorMessage
      : 'Simulated internal server error',
    applyTo: Array.isArray(simulation.applyTo) ? simulation.applyTo : []
  };
}

function logSimulation(mode, req, extra = {}) {
  logger.warn('Simulated failure applied', {
    requestId: req.requestId,
    mode,
    path: req.path,
    method: req.method,
    ...extra
  });
}

/**
 * Hold the request open without ever responding.
 * When `destroyAfterMs > 0` the socket is destroyed after that delay, which
 * surfaces as a connection reset on the client instead of a read timeout.
 */
function holdRequestOpen(req, res, destroyAfterMs) {
  // Disable the per-socket inactivity timeout so the request really hangs
  if (req.socket && typeof req.socket.setTimeout === 'function') {
    req.socket.setTimeout(0);
  }

  if (destroyAfterMs > 0) {
    const timer = setTimeout(() => {
      logger.warn('Simulated timeout - destroying socket', {
        requestId: req.requestId,
        path: req.path,
        method: req.method,
        afterMs: destroyAfterMs
      });

      if (req.socket && !req.socket.destroyed) {
        req.socket.destroy();
      }
    }, destroyAfterMs);

    if (typeof timer.unref === 'function') timer.unref();

    // Client gave up first - drop the timer
    res.on('close', () => clearTimeout(timer));
  }

  // Deliberately no next() and no response: the request stays open.
}

function sendSimulatedError(req, res, status, message) {
  return res.status(status).json({
    status: 'failure',
    message
  });
}

/**
 * Wait `delayMs`, then run `callback` - unless the client disconnects first.
 */
function delayThen(req, res, delayMs, callback) {
  const timer = setTimeout(() => {
    res.removeListener('close', onClose);
    callback();
  }, delayMs);

  function onClose() {
    clearTimeout(timer);
  }

  // Client aborted while we were waiting - do not continue into the routes
  res.on('close', onClose);
}

/**
 * The simulation middleware. Mount BEFORE the authentication routes.
 */
function simulationMiddleware(req, res, next) {
  if (isControlPath(req.path)) {
    return next();
  }

  // -------------------------------------------------------------------------
  // Per-request overrides
  // -------------------------------------------------------------------------
  const timeoutHeader = String(req.headers['x-mock-timeout'] || '').trim().toLowerCase();
  const timeoutRequested = TRUTHY_HEADER_VALUES.includes(timeoutHeader);

  const hasDelayOverride = req.query._delay !== undefined;
  const hasStatusOverride = req.query._status !== undefined;

  let delayOverride = null;
  if (hasDelayOverride) {
    const rawDelay = Array.isArray(req.query._delay) ? req.query._delay[0] : req.query._delay;
    const parsedDelay = Number.parseInt(rawDelay, 10);

    if (!Number.isFinite(parsedDelay) || parsedDelay < 0) {
      return res.status(400).json({
        status: 'failure',
        message: 'Invalid _delay override',
        details: {
          received: rawDelay,
          expected: `integer between 0 and ${MAX_DELAY_MS}`
        }
      });
    }

    delayOverride = Math.min(parsedDelay, MAX_DELAY_MS);
  }

  let statusOverride = null;
  if (hasStatusOverride) {
    const rawStatus = Array.isArray(req.query._status) ? req.query._status[0] : req.query._status;
    const parsedStatus = Number.parseInt(rawStatus, 10);

    if (!Number.isInteger(parsedStatus) || parsedStatus < MIN_ERROR_STATUS || parsedStatus > MAX_ERROR_STATUS) {
      return res.status(400).json({
        status: 'failure',
        message: 'Invalid _status override',
        details: {
          received: rawStatus,
          expected: `integer between ${MIN_ERROR_STATUS} and ${MAX_ERROR_STATUS}`
        }
      });
    }

    statusOverride = parsedStatus;
  }

  // x-mock-timeout wins over everything else for this request
  if (timeoutRequested) {
    logSimulation('timeout', req, { source: 'header:x-mock-timeout', delayMs: delayOverride || 0 });
    return holdRequestOpen(req, res, delayOverride || 0);
  }

  // -------------------------------------------------------------------------
  // Global simulation config
  // -------------------------------------------------------------------------
  const simulation = getSimulationConfig();
  const simulationApplies = simulation.mode !== 'none' && isWithinApplyTo(req.path, simulation.applyTo);

  if (simulationApplies && simulation.mode === 'timeout' && statusOverride === null) {
    logSimulation('timeout', req, { source: 'config', delayMs: simulation.delayMs });
    return holdRequestOpen(req, res, delayOverride !== null ? delayOverride : simulation.delayMs);
  }

  // A per-request _delay always wins over the configured delay
  let effectiveDelay = 0;
  if (delayOverride !== null) {
    effectiveDelay = delayOverride;
  } else if (simulationApplies && simulation.mode === 'delay') {
    effectiveDelay = simulation.delayMs;
  }

  const proceed = () => {
    if (statusOverride !== null) {
      logSimulation('error', req, { source: 'query:_status', errorStatus: statusOverride });
      return sendSimulatedError(req, res, statusOverride, 'Simulated error via _status');
    }

    if (simulationApplies && simulation.mode === 'error') {
      logSimulation('error', req, {
        source: 'config',
        errorStatus: simulation.errorStatus,
        errorMessage: simulation.errorMessage
      });
      return sendSimulatedError(req, res, simulation.errorStatus, simulation.errorMessage);
    }

    return next();
  };

  if (effectiveDelay > 0) {
    logSimulation('delay', req, {
      source: delayOverride !== null ? 'query:_delay' : 'config',
      delayMs: effectiveDelay
    });
    return delayThen(req, res, effectiveDelay, proceed);
  }

  return proceed();
}

module.exports = {
  simulationMiddleware,
  isControlPath,
  isWithinApplyTo,
  pathMatchesPrefix,
  getSimulationConfig,
  CONTROL_PATH_PREFIXES,
  VALID_SIMULATION_MODES,
  MAX_DELAY_MS,
  MIN_ERROR_STATUS,
  MAX_ERROR_STATUS
};

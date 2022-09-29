(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
  typeof define === 'function' && define.amd ? define(['exports'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.LDClient = {}));
})(this, (function (exports) { 'use strict';

  function createCustomError(name) {
    function CustomError(message, code) {
      Error.captureStackTrace && Error.captureStackTrace(this, this.constructor);
      this.message = message;
      this.code = code;
    }

    CustomError.prototype = new Error();
    CustomError.prototype.name = name;
    CustomError.prototype.constructor = CustomError;

    return CustomError;
  }

  const LDUnexpectedResponseError = createCustomError('LaunchDarklyUnexpectedResponseError');
  const LDInvalidEnvironmentIdError = createCustomError('LaunchDarklyInvalidEnvironmentIdError');
  const LDInvalidUserError = createCustomError('LaunchDarklyInvalidUserError');
  const LDInvalidEventKeyError = createCustomError('LaunchDarklyInvalidEventKeyError');
  const LDInvalidArgumentError = createCustomError('LaunchDarklyInvalidArgumentError');
  const LDFlagFetchError = createCustomError('LaunchDarklyFlagFetchError');
  const LDInvalidDataError = createCustomError('LaunchDarklyInvalidDataError');

  function isHttpErrorRecoverable(status) {
    if (status >= 400 && status < 500) {
      return status === 400 || status === 408 || status === 429;
    }
    return true;
  }

  var errors = {
    LDUnexpectedResponseError,
    LDInvalidEnvironmentIdError,
    LDInvalidUserError,
    LDInvalidEventKeyError,
    LDInvalidArgumentError,
    LDInvalidDataError,
    LDFlagFetchError,
    isHttpErrorRecoverable,
  };

  var byteLength_1 = byteLength;
  var toByteArray_1 = toByteArray;
  var fromByteArray_1 = fromByteArray;

  var lookup = [];
  var revLookup = [];
  var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array;

  var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (var i$1 = 0, len = code.length; i$1 < len; ++i$1) {
    lookup[i$1] = code[i$1];
    revLookup[code.charCodeAt(i$1)] = i$1;
  }

  // Support decoding URL-safe base64 strings, as Node.js does.
  // See: https://en.wikipedia.org/wiki/Base64#URL_applications
  revLookup['-'.charCodeAt(0)] = 62;
  revLookup['_'.charCodeAt(0)] = 63;

  function getLens (b64) {
    var len = b64.length;

    if (len % 4 > 0) {
      throw new Error('Invalid string. Length must be a multiple of 4')
    }

    // Trim off extra bytes after placeholder bytes are found
    // See: https://github.com/beatgammit/base64-js/issues/42
    var validLen = b64.indexOf('=');
    if (validLen === -1) validLen = len;

    var placeHoldersLen = validLen === len
      ? 0
      : 4 - (validLen % 4);

    return [validLen, placeHoldersLen]
  }

  // base64 is 4/3 + up to two characters of the original data
  function byteLength (b64) {
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
  }

  function _byteLength (b64, validLen, placeHoldersLen) {
    return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
  }

  function toByteArray (b64) {
    var tmp;
    var lens = getLens(b64);
    var validLen = lens[0];
    var placeHoldersLen = lens[1];

    var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));

    var curByte = 0;

    // if there are placeholders, only get up to the last complete 4 chars
    var len = placeHoldersLen > 0
      ? validLen - 4
      : validLen;

    var i;
    for (i = 0; i < len; i += 4) {
      tmp =
        (revLookup[b64.charCodeAt(i)] << 18) |
        (revLookup[b64.charCodeAt(i + 1)] << 12) |
        (revLookup[b64.charCodeAt(i + 2)] << 6) |
        revLookup[b64.charCodeAt(i + 3)];
      arr[curByte++] = (tmp >> 16) & 0xFF;
      arr[curByte++] = (tmp >> 8) & 0xFF;
      arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 2) {
      tmp =
        (revLookup[b64.charCodeAt(i)] << 2) |
        (revLookup[b64.charCodeAt(i + 1)] >> 4);
      arr[curByte++] = tmp & 0xFF;
    }

    if (placeHoldersLen === 1) {
      tmp =
        (revLookup[b64.charCodeAt(i)] << 10) |
        (revLookup[b64.charCodeAt(i + 1)] << 4) |
        (revLookup[b64.charCodeAt(i + 2)] >> 2);
      arr[curByte++] = (tmp >> 8) & 0xFF;
      arr[curByte++] = tmp & 0xFF;
    }

    return arr
  }

  function tripletToBase64 (num) {
    return lookup[num >> 18 & 0x3F] +
      lookup[num >> 12 & 0x3F] +
      lookup[num >> 6 & 0x3F] +
      lookup[num & 0x3F]
  }

  function encodeChunk (uint8, start, end) {
    var tmp;
    var output = [];
    for (var i = start; i < end; i += 3) {
      tmp =
        ((uint8[i] << 16) & 0xFF0000) +
        ((uint8[i + 1] << 8) & 0xFF00) +
        (uint8[i + 2] & 0xFF);
      output.push(tripletToBase64(tmp));
    }
    return output.join('')
  }

  function fromByteArray (uint8) {
    var tmp;
    var len = uint8.length;
    var extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
    var parts = [];
    var maxChunkLength = 16383; // must be multiple of 3

    // go through the array every three bytes, we'll deal with trailing stuff later
    for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
      parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)));
    }

    // pad the end with zeros, but make sure to not forget the extra bytes
    if (extraBytes === 1) {
      tmp = uint8[len - 1];
      parts.push(
        lookup[tmp >> 2] +
        lookup[(tmp << 4) & 0x3F] +
        '=='
      );
    } else if (extraBytes === 2) {
      tmp = (uint8[len - 2] << 8) + uint8[len - 1];
      parts.push(
        lookup[tmp >> 10] +
        lookup[(tmp >> 4) & 0x3F] +
        lookup[(tmp << 2) & 0x3F] +
        '='
      );
    }

    return parts.join('')
  }

  var base64Js = {
  	byteLength: byteLength_1,
  	toByteArray: toByteArray_1,
  	fromByteArray: fromByteArray_1
  };

  var isArray = Array.isArray;
  var keyList = Object.keys;
  var hasProp = Object.prototype.hasOwnProperty;

  var fastDeepEqual = function equal(a, b) {
    if (a === b) return true;

    if (a && b && typeof a == 'object' && typeof b == 'object') {
      var arrA = isArray(a)
        , arrB = isArray(b)
        , i
        , length
        , key;

      if (arrA && arrB) {
        length = a.length;
        if (length != b.length) return false;
        for (i = length; i-- !== 0;)
          if (!equal(a[i], b[i])) return false;
        return true;
      }

      if (arrA != arrB) return false;

      var dateA = a instanceof Date
        , dateB = b instanceof Date;
      if (dateA != dateB) return false;
      if (dateA && dateB) return a.getTime() == b.getTime();

      var regexpA = a instanceof RegExp
        , regexpB = b instanceof RegExp;
      if (regexpA != regexpB) return false;
      if (regexpA && regexpB) return a.toString() == b.toString();

      var keys = keyList(a);
      length = keys.length;

      if (length !== keyList(b).length)
        return false;

      for (i = length; i-- !== 0;)
        if (!hasProp.call(b, keys[i])) return false;

      for (i = length; i-- !== 0;) {
        key = keys[i];
        if (!equal(a[key], b[key])) return false;
      }

      return true;
    }

    return a!==a && b!==b;
  };

  const userAttrsToStringify = ['key', 'secondary', 'ip', 'country', 'email', 'firstName', 'lastName', 'avatar', 'name'];

  function appendUrlPath$2(baseUrl, path) {
    // Ensure that URL concatenation is done correctly regardless of whether the
    // base URL has a trailing slash or not.
    const trimBaseUrl = baseUrl.endsWith('/') ? baseUrl.substring(0, baseUrl.length - 1) : baseUrl;
    return trimBaseUrl + (path.startsWith('/') ? '' : '/') + path;
  }

  // See http://ecmanaut.blogspot.com/2006/07/encoding-decoding-utf8-in-javascript.html
  function btoa(s) {
    const escaped = unescape(encodeURIComponent(s));
    return base64Js.fromByteArray(stringToBytes$1(escaped));
  }

  function stringToBytes$1(s) {
    const b = [];
    for (let i = 0; i < s.length; i++) {
      b.push(s.charCodeAt(i));
    }
    return b;
  }

  function base64URLEncode$1(s) {
    return (
      btoa(s)
        // eslint-disable-next-line
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
    );
  }

  function clone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  function deepEquals(a, b) {
    return fastDeepEqual(a, b);
  }

  // Events emitted in LDClient's initialize method will happen before the consumer
  // can register a listener, so defer them to next tick.
  function onNextTick(cb) {
    setTimeout(cb, 0);
  }

  /**
   * Wrap a promise to invoke an optional callback upon resolution or rejection.
   *
   * This function assumes the callback follows the Node.js callback type: (err, value) => void
   *
   * If a callback is provided:
   *   - if the promise is resolved, invoke the callback with (null, value)
   *   - if the promise is rejected, invoke the callback with (error, null)
   *
   * @param {Promise<any>} promise
   * @param {Function} callback
   * @returns Promise<any> | undefined
   */
  function wrapPromiseCallback(promise, callback) {
    const ret = promise.then(
      value => {
        if (callback) {
          setTimeout(() => {
            callback(null, value);
          }, 0);
        }
        return value;
      },
      error => {
        if (callback) {
          setTimeout(() => {
            callback(error, null);
          }, 0);
        } else {
          return Promise.reject(error);
        }
      }
    );

    return !callback ? ret : undefined;
  }

  /**
   * Takes a map of flag keys to values, and returns the more verbose structure used by the
   * client stream.
   */
  function transformValuesToVersionedValues(flags) {
    const ret = {};
    for (const key in flags) {
      if (objectHasOwnProperty$1(flags, key)) {
        ret[key] = { value: flags[key], version: 0 };
      }
    }
    return ret;
  }

  /**
   * Converts the internal flag state map to a simple map of flag keys to values.
   */
  function transformVersionedValuesToValues(flagsState) {
    const ret = {};
    for (const key in flagsState) {
      if (objectHasOwnProperty$1(flagsState, key)) {
        ret[key] = flagsState[key].value;
      }
    }
    return ret;
  }

  /**
   * Returns an array of event groups each of which can be safely URL-encoded
   * without hitting the safe maximum URL length of certain browsers.
   *
   * @param {number} maxLength maximum URL length targeted
   * @param {Array[Object}]} events queue of events to divide
   * @returns Array[Array[Object]]
   */
  function chunkEventsForUrl(maxLength, events) {
    const allEvents = events.slice(0);
    const allChunks = [];
    let remainingSpace = maxLength;
    let chunk;

    while (allEvents.length > 0) {
      chunk = [];

      while (remainingSpace > 0) {
        const event = allEvents.shift();
        if (!event) {
          break;
        }
        remainingSpace = remainingSpace - base64URLEncode$1(JSON.stringify(event)).length;
        // If we are over the max size, put this one back on the queue
        // to try in the next round, unless this event alone is larger
        // than the limit, in which case, screw it, and try it anyway.
        if (remainingSpace < 0 && chunk.length > 0) {
          allEvents.unshift(event);
        } else {
          chunk.push(event);
        }
      }

      remainingSpace = maxLength;
      allChunks.push(chunk);
    }

    return allChunks;
  }

  function getLDUserAgentString$1(platform) {
    const version = platform.version || '?';
    return platform.userAgent + '/' + version;
  }

  function extend(...objects) {
    return objects.reduce((acc, obj) => ({ ...acc, ...obj }), {});
  }

  function objectHasOwnProperty$1(object, name) {
    return Object.prototype.hasOwnProperty.call(object, name);
  }

  function sanitizeContext(context) {
    if (!context) {
      return context;
    }
    let newContext;
    // Only stringify user attributes for legacy users.
    if (context.kind === null || context.kind === undefined) {
      userAttrsToStringify.forEach(attr => {
        const value = context[attr];
        if (value !== undefined && typeof value !== 'string') {
          newContext = newContext || { ...context };
          newContext[attr] = String(value);
        }
      });
    }

    return newContext || context;
  }

  var utils = {
    appendUrlPath: appendUrlPath$2,
    base64URLEncode: base64URLEncode$1,
    btoa,
    chunkEventsForUrl,
    clone,
    deepEquals,
    extend,
    getLDUserAgentString: getLDUserAgentString$1,
    objectHasOwnProperty: objectHasOwnProperty$1,
    onNextTick,
    sanitizeContext,
    transformValuesToVersionedValues,
    transformVersionedValuesToValues,
    wrapPromiseCallback,
  };

  // Unique ID creation requires a high quality random # generator. In the browser we therefore
  // require the crypto API and do not support built-in fallback to lower quality random number
  // generators (like Math.random()).
  var getRandomValues;
  var rnds8 = new Uint8Array(16);
  function rng() {
    // lazy load so that environments that need to polyfill have a chance to do so
    if (!getRandomValues) {
      // getRandomValues needs to be invoked in a context where "this" is a Crypto implementation. Also,
      // find the complete implementation of crypto (msCrypto) on IE11.
      getRandomValues = typeof crypto !== 'undefined' && crypto.getRandomValues && crypto.getRandomValues.bind(crypto) || typeof msCrypto !== 'undefined' && typeof msCrypto.getRandomValues === 'function' && msCrypto.getRandomValues.bind(msCrypto);

      if (!getRandomValues) {
        throw new Error('crypto.getRandomValues() not supported. See https://github.com/uuidjs/uuid#getrandomvalues-not-supported');
      }
    }

    return getRandomValues(rnds8);
  }

  var REGEX = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;

  function validate$1(uuid) {
    return typeof uuid === 'string' && REGEX.test(uuid);
  }

  /**
   * Convert array of 16 byte values to UUID string format of the form:
   * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
   */

  var byteToHex = [];

  for (var i = 0; i < 256; ++i) {
    byteToHex.push((i + 0x100).toString(16).substr(1));
  }

  function stringify(arr) {
    var offset = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 0;
    // Note: Be careful editing this code!  It's been tuned for performance
    // and works in ways you may not expect. See https://github.com/uuidjs/uuid/pull/434
    var uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase(); // Consistency check for valid UUID.  If this throws, it's likely due to one
    // of the following:
    // - One or more input array values don't map to a hex octet (leading to
    // "undefined" in the uuid)
    // - Invalid input values for the RFC `version` or `variant` fields

    if (!validate$1(uuid)) {
      throw TypeError('Stringified UUID is invalid');
    }

    return uuid;
  }

  //
  // Inspired by https://github.com/LiosK/UUID.js
  // and http://docs.python.org/library/uuid.html

  var _nodeId;

  var _clockseq; // Previous uuid creation time


  var _lastMSecs = 0;
  var _lastNSecs = 0; // See https://github.com/uuidjs/uuid for API details

  function v1(options, buf, offset) {
    var i = buf && offset || 0;
    var b = buf || new Array(16);
    options = options || {};
    var node = options.node || _nodeId;
    var clockseq = options.clockseq !== undefined ? options.clockseq : _clockseq; // node and clockseq need to be initialized to random values if they're not
    // specified.  We do this lazily to minimize issues related to insufficient
    // system entropy.  See #189

    if (node == null || clockseq == null) {
      var seedBytes = options.random || (options.rng || rng)();

      if (node == null) {
        // Per 4.5, create and 48-bit node id, (47 random bits + multicast bit = 1)
        node = _nodeId = [seedBytes[0] | 0x01, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
      }

      if (clockseq == null) {
        // Per 4.2.2, randomize (14 bit) clockseq
        clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 0x3fff;
      }
    } // UUID timestamps are 100 nano-second units since the Gregorian epoch,
    // (1582-10-15 00:00).  JSNumbers aren't precise enough for this, so
    // time is handled internally as 'msecs' (integer milliseconds) and 'nsecs'
    // (100-nanoseconds offset from msecs) since unix epoch, 1970-01-01 00:00.


    var msecs = options.msecs !== undefined ? options.msecs : Date.now(); // Per 4.2.1.2, use count of uuid's generated during the current clock
    // cycle to simulate higher resolution clock

    var nsecs = options.nsecs !== undefined ? options.nsecs : _lastNSecs + 1; // Time since last uuid creation (in msecs)

    var dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 10000; // Per 4.2.1.2, Bump clockseq on clock regression

    if (dt < 0 && options.clockseq === undefined) {
      clockseq = clockseq + 1 & 0x3fff;
    } // Reset nsecs if clock regresses (new clockseq) or we've moved onto a new
    // time interval


    if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === undefined) {
      nsecs = 0;
    } // Per 4.2.1.2 Throw error if too many uuids are requested


    if (nsecs >= 10000) {
      throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
    }

    _lastMSecs = msecs;
    _lastNSecs = nsecs;
    _clockseq = clockseq; // Per 4.1.4 - Convert from unix epoch to Gregorian epoch

    msecs += 12219292800000; // `time_low`

    var tl = ((msecs & 0xfffffff) * 10000 + nsecs) % 0x100000000;
    b[i++] = tl >>> 24 & 0xff;
    b[i++] = tl >>> 16 & 0xff;
    b[i++] = tl >>> 8 & 0xff;
    b[i++] = tl & 0xff; // `time_mid`

    var tmh = msecs / 0x100000000 * 10000 & 0xfffffff;
    b[i++] = tmh >>> 8 & 0xff;
    b[i++] = tmh & 0xff; // `time_high_and_version`

    b[i++] = tmh >>> 24 & 0xf | 0x10; // include version

    b[i++] = tmh >>> 16 & 0xff; // `clock_seq_hi_and_reserved` (Per 4.2.2 - include variant)

    b[i++] = clockseq >>> 8 | 0x80; // `clock_seq_low`

    b[i++] = clockseq & 0xff; // `node`

    for (var n = 0; n < 6; ++n) {
      b[i + n] = node[n];
    }

    return buf || stringify(b);
  }

  function parse(uuid) {
    if (!validate$1(uuid)) {
      throw TypeError('Invalid UUID');
    }

    var v;
    var arr = new Uint8Array(16); // Parse ########-....-....-....-............

    arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
    arr[1] = v >>> 16 & 0xff;
    arr[2] = v >>> 8 & 0xff;
    arr[3] = v & 0xff; // Parse ........-####-....-....-............

    arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
    arr[5] = v & 0xff; // Parse ........-....-####-....-............

    arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
    arr[7] = v & 0xff; // Parse ........-....-....-####-............

    arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
    arr[9] = v & 0xff; // Parse ........-....-....-....-############
    // (Use "/" to avoid 32-bit truncation when bit-shifting high-order bytes)

    arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 0x10000000000 & 0xff;
    arr[11] = v / 0x100000000 & 0xff;
    arr[12] = v >>> 24 & 0xff;
    arr[13] = v >>> 16 & 0xff;
    arr[14] = v >>> 8 & 0xff;
    arr[15] = v & 0xff;
    return arr;
  }

  function stringToBytes(str) {
    str = unescape(encodeURIComponent(str)); // UTF8 escape

    var bytes = [];

    for (var i = 0; i < str.length; ++i) {
      bytes.push(str.charCodeAt(i));
    }

    return bytes;
  }

  var DNS = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
  var URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';
  function v35 (name, version, hashfunc) {
    function generateUUID(value, namespace, buf, offset) {
      if (typeof value === 'string') {
        value = stringToBytes(value);
      }

      if (typeof namespace === 'string') {
        namespace = parse(namespace);
      }

      if (namespace.length !== 16) {
        throw TypeError('Namespace must be array-like (16 iterable integer values, 0-255)');
      } // Compute hash of namespace and value, Per 4.3
      // Future: Use spread syntax when supported on all platforms, e.g. `bytes =
      // hashfunc([...namespace, ... value])`


      var bytes = new Uint8Array(16 + value.length);
      bytes.set(namespace);
      bytes.set(value, namespace.length);
      bytes = hashfunc(bytes);
      bytes[6] = bytes[6] & 0x0f | version;
      bytes[8] = bytes[8] & 0x3f | 0x80;

      if (buf) {
        offset = offset || 0;

        for (var i = 0; i < 16; ++i) {
          buf[offset + i] = bytes[i];
        }

        return buf;
      }

      return stringify(bytes);
    } // Function#name is not settable on some platforms (#270)


    try {
      generateUUID.name = name; // eslint-disable-next-line no-empty
    } catch (err) {} // For CommonJS default export support


    generateUUID.DNS = DNS;
    generateUUID.URL = URL;
    return generateUUID;
  }

  /*
   * Browser-compatible JavaScript MD5
   *
   * Modification of JavaScript MD5
   * https://github.com/blueimp/JavaScript-MD5
   *
   * Copyright 2011, Sebastian Tschan
   * https://blueimp.net
   *
   * Licensed under the MIT license:
   * https://opensource.org/licenses/MIT
   *
   * Based on
   * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
   * Digest Algorithm, as defined in RFC 1321.
   * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
   * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
   * Distributed under the BSD License
   * See http://pajhome.org.uk/crypt/md5 for more info.
   */
  function md5(bytes) {
    if (typeof bytes === 'string') {
      var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

      bytes = new Uint8Array(msg.length);

      for (var i = 0; i < msg.length; ++i) {
        bytes[i] = msg.charCodeAt(i);
      }
    }

    return md5ToHexEncodedArray(wordsToMd5(bytesToWords(bytes), bytes.length * 8));
  }
  /*
   * Convert an array of little-endian words to an array of bytes
   */


  function md5ToHexEncodedArray(input) {
    var output = [];
    var length32 = input.length * 32;
    var hexTab = '0123456789abcdef';

    for (var i = 0; i < length32; i += 8) {
      var x = input[i >> 5] >>> i % 32 & 0xff;
      var hex = parseInt(hexTab.charAt(x >>> 4 & 0x0f) + hexTab.charAt(x & 0x0f), 16);
      output.push(hex);
    }

    return output;
  }
  /**
   * Calculate output length with padding and bit length
   */


  function getOutputLength(inputLength8) {
    return (inputLength8 + 64 >>> 9 << 4) + 14 + 1;
  }
  /*
   * Calculate the MD5 of an array of little-endian words, and a bit length.
   */


  function wordsToMd5(x, len) {
    /* append padding */
    x[len >> 5] |= 0x80 << len % 32;
    x[getOutputLength(len) - 1] = len;
    var a = 1732584193;
    var b = -271733879;
    var c = -1732584194;
    var d = 271733878;

    for (var i = 0; i < x.length; i += 16) {
      var olda = a;
      var oldb = b;
      var oldc = c;
      var oldd = d;
      a = md5ff(a, b, c, d, x[i], 7, -680876936);
      d = md5ff(d, a, b, c, x[i + 1], 12, -389564586);
      c = md5ff(c, d, a, b, x[i + 2], 17, 606105819);
      b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330);
      a = md5ff(a, b, c, d, x[i + 4], 7, -176418897);
      d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426);
      c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341);
      b = md5ff(b, c, d, a, x[i + 7], 22, -45705983);
      a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416);
      d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417);
      c = md5ff(c, d, a, b, x[i + 10], 17, -42063);
      b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162);
      a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682);
      d = md5ff(d, a, b, c, x[i + 13], 12, -40341101);
      c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290);
      b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329);
      a = md5gg(a, b, c, d, x[i + 1], 5, -165796510);
      d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632);
      c = md5gg(c, d, a, b, x[i + 11], 14, 643717713);
      b = md5gg(b, c, d, a, x[i], 20, -373897302);
      a = md5gg(a, b, c, d, x[i + 5], 5, -701558691);
      d = md5gg(d, a, b, c, x[i + 10], 9, 38016083);
      c = md5gg(c, d, a, b, x[i + 15], 14, -660478335);
      b = md5gg(b, c, d, a, x[i + 4], 20, -405537848);
      a = md5gg(a, b, c, d, x[i + 9], 5, 568446438);
      d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690);
      c = md5gg(c, d, a, b, x[i + 3], 14, -187363961);
      b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501);
      a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467);
      d = md5gg(d, a, b, c, x[i + 2], 9, -51403784);
      c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473);
      b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734);
      a = md5hh(a, b, c, d, x[i + 5], 4, -378558);
      d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463);
      c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562);
      b = md5hh(b, c, d, a, x[i + 14], 23, -35309556);
      a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060);
      d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353);
      c = md5hh(c, d, a, b, x[i + 7], 16, -155497632);
      b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640);
      a = md5hh(a, b, c, d, x[i + 13], 4, 681279174);
      d = md5hh(d, a, b, c, x[i], 11, -358537222);
      c = md5hh(c, d, a, b, x[i + 3], 16, -722521979);
      b = md5hh(b, c, d, a, x[i + 6], 23, 76029189);
      a = md5hh(a, b, c, d, x[i + 9], 4, -640364487);
      d = md5hh(d, a, b, c, x[i + 12], 11, -421815835);
      c = md5hh(c, d, a, b, x[i + 15], 16, 530742520);
      b = md5hh(b, c, d, a, x[i + 2], 23, -995338651);
      a = md5ii(a, b, c, d, x[i], 6, -198630844);
      d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415);
      c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905);
      b = md5ii(b, c, d, a, x[i + 5], 21, -57434055);
      a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571);
      d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606);
      c = md5ii(c, d, a, b, x[i + 10], 15, -1051523);
      b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799);
      a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359);
      d = md5ii(d, a, b, c, x[i + 15], 10, -30611744);
      c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380);
      b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649);
      a = md5ii(a, b, c, d, x[i + 4], 6, -145523070);
      d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379);
      c = md5ii(c, d, a, b, x[i + 2], 15, 718787259);
      b = md5ii(b, c, d, a, x[i + 9], 21, -343485551);
      a = safeAdd(a, olda);
      b = safeAdd(b, oldb);
      c = safeAdd(c, oldc);
      d = safeAdd(d, oldd);
    }

    return [a, b, c, d];
  }
  /*
   * Convert an array bytes to an array of little-endian words
   * Characters >255 have their high-byte silently ignored.
   */


  function bytesToWords(input) {
    if (input.length === 0) {
      return [];
    }

    var length8 = input.length * 8;
    var output = new Uint32Array(getOutputLength(length8));

    for (var i = 0; i < length8; i += 8) {
      output[i >> 5] |= (input[i / 8] & 0xff) << i % 32;
    }

    return output;
  }
  /*
   * Add integers, wrapping at 2^32. This uses 16-bit operations internally
   * to work around bugs in some JS interpreters.
   */


  function safeAdd(x, y) {
    var lsw = (x & 0xffff) + (y & 0xffff);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return msw << 16 | lsw & 0xffff;
  }
  /*
   * Bitwise rotate a 32-bit number to the left.
   */


  function bitRotateLeft(num, cnt) {
    return num << cnt | num >>> 32 - cnt;
  }
  /*
   * These functions implement the four basic operations the algorithm uses.
   */


  function md5cmn(q, a, b, x, s, t) {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b);
  }

  function md5ff(a, b, c, d, x, s, t) {
    return md5cmn(b & c | ~b & d, a, b, x, s, t);
  }

  function md5gg(a, b, c, d, x, s, t) {
    return md5cmn(b & d | c & ~d, a, b, x, s, t);
  }

  function md5hh(a, b, c, d, x, s, t) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t);
  }

  function md5ii(a, b, c, d, x, s, t) {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t);
  }

  var v3 = v35('v3', 0x30, md5);
  var v3$1 = v3;

  function v4(options, buf, offset) {
    options = options || {};
    var rnds = options.random || (options.rng || rng)(); // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`

    rnds[6] = rnds[6] & 0x0f | 0x40;
    rnds[8] = rnds[8] & 0x3f | 0x80; // Copy bytes to buffer, if provided

    if (buf) {
      offset = offset || 0;

      for (var i = 0; i < 16; ++i) {
        buf[offset + i] = rnds[i];
      }

      return buf;
    }

    return stringify(rnds);
  }

  // Adapted from Chris Veness' SHA1 code at
  // http://www.movable-type.co.uk/scripts/sha1.html
  function f(s, x, y, z) {
    switch (s) {
      case 0:
        return x & y ^ ~x & z;

      case 1:
        return x ^ y ^ z;

      case 2:
        return x & y ^ x & z ^ y & z;

      case 3:
        return x ^ y ^ z;
    }
  }

  function ROTL(x, n) {
    return x << n | x >>> 32 - n;
  }

  function sha1(bytes) {
    var K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
    var H = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

    if (typeof bytes === 'string') {
      var msg = unescape(encodeURIComponent(bytes)); // UTF8 escape

      bytes = [];

      for (var i = 0; i < msg.length; ++i) {
        bytes.push(msg.charCodeAt(i));
      }
    } else if (!Array.isArray(bytes)) {
      // Convert Array-like to Array
      bytes = Array.prototype.slice.call(bytes);
    }

    bytes.push(0x80);
    var l = bytes.length / 4 + 2;
    var N = Math.ceil(l / 16);
    var M = new Array(N);

    for (var _i = 0; _i < N; ++_i) {
      var arr = new Uint32Array(16);

      for (var j = 0; j < 16; ++j) {
        arr[j] = bytes[_i * 64 + j * 4] << 24 | bytes[_i * 64 + j * 4 + 1] << 16 | bytes[_i * 64 + j * 4 + 2] << 8 | bytes[_i * 64 + j * 4 + 3];
      }

      M[_i] = arr;
    }

    M[N - 1][14] = (bytes.length - 1) * 8 / Math.pow(2, 32);
    M[N - 1][14] = Math.floor(M[N - 1][14]);
    M[N - 1][15] = (bytes.length - 1) * 8 & 0xffffffff;

    for (var _i2 = 0; _i2 < N; ++_i2) {
      var W = new Uint32Array(80);

      for (var t = 0; t < 16; ++t) {
        W[t] = M[_i2][t];
      }

      for (var _t = 16; _t < 80; ++_t) {
        W[_t] = ROTL(W[_t - 3] ^ W[_t - 8] ^ W[_t - 14] ^ W[_t - 16], 1);
      }

      var a = H[0];
      var b = H[1];
      var c = H[2];
      var d = H[3];
      var e = H[4];

      for (var _t2 = 0; _t2 < 80; ++_t2) {
        var s = Math.floor(_t2 / 20);
        var T = ROTL(a, 5) + f(s, b, c, d) + e + K[s] + W[_t2] >>> 0;
        e = d;
        d = c;
        c = ROTL(b, 30) >>> 0;
        b = a;
        a = T;
      }

      H[0] = H[0] + a >>> 0;
      H[1] = H[1] + b >>> 0;
      H[2] = H[2] + c >>> 0;
      H[3] = H[3] + d >>> 0;
      H[4] = H[4] + e >>> 0;
    }

    return [H[0] >> 24 & 0xff, H[0] >> 16 & 0xff, H[0] >> 8 & 0xff, H[0] & 0xff, H[1] >> 24 & 0xff, H[1] >> 16 & 0xff, H[1] >> 8 & 0xff, H[1] & 0xff, H[2] >> 24 & 0xff, H[2] >> 16 & 0xff, H[2] >> 8 & 0xff, H[2] & 0xff, H[3] >> 24 & 0xff, H[3] >> 16 & 0xff, H[3] >> 8 & 0xff, H[3] & 0xff, H[4] >> 24 & 0xff, H[4] >> 16 & 0xff, H[4] >> 8 & 0xff, H[4] & 0xff];
  }

  var v5 = v35('v5', 0x50, sha1);
  var v5$1 = v5;

  var nil = '00000000-0000-0000-0000-000000000000';

  function version$1(uuid) {
    if (!validate$1(uuid)) {
      throw TypeError('Invalid UUID');
    }

    return parseInt(uuid.substr(14, 1), 16);
  }

  var esmBrowser = /*#__PURE__*/Object.freeze({
    __proto__: null,
    v1: v1,
    v3: v3$1,
    v4: v4,
    v5: v5$1,
    NIL: nil,
    version: version$1,
    validate: validate$1,
    stringify: stringify,
    parse: parse
  });

  const logLevels = ['debug', 'info', 'warn', 'error', 'none'];

  /**
   * A simple logger that writes to stderr.
   */
  function commonBasicLogger$2(options, formatFn) {
    if (options && options.destination && typeof options.destination !== 'function') {
      throw new Error('destination for basicLogger was set to a non-function');
    }

    function toConsole(methodName) {
      // The global console variable is not guaranteed to be defined at all times in all browsers:
      // https://www.beyondjava.net/console-log-surprises-with-internet-explorer-11-and-edge
      return function(line) {
        if (console && console[methodName]) {
          console[methodName].call(console, line);
        }
      };
    }
    const destinations =
      options && options.destination
        ? [options.destination, options.destination, options.destination, options.destination]
        : [toConsole('log'), toConsole('info'), toConsole('warn'), toConsole('error')];
    const prependLevelToMessage = !!(options && options.destination); // if we're writing to console.warn, etc. we don't need the prefix
    const prefix =
      !options || options.prefix === undefined || options.prefix === null ? '[LaunchDarkly] ' : options.prefix;

    let minLevel = 1; // default is 'info'
    if (options && options.level) {
      for (let i = 0; i < logLevels.length; i++) {
        if (logLevels[i] === options.level) {
          minLevel = i;
        }
      }
    }

    function write(levelIndex, levelName, args) {
      if (args.length < 1) {
        return;
      }
      let line;
      const fullPrefix = prependLevelToMessage ? levelName + ': ' + prefix : prefix;
      if (args.length === 1 || !formatFn) {
        line = fullPrefix + args[0];
      } else {
        const tempArgs = [...args];
        tempArgs[0] = fullPrefix + tempArgs[0];
        line = formatFn(...tempArgs);
      }
      try {
        destinations[levelIndex](line);
      } catch (err) {
        console &&
          console.log &&
          console.log("[LaunchDarkly] Configured logger's " + levelName + ' method threw an exception: ' + err);
      }
    }

    const logger = {};
    for (let i = 0; i < logLevels.length; i++) {
      const levelName = logLevels[i];
      if (levelName !== 'none') {
        if (i < minLevel) {
          logger[levelName] = () => {};
        } else {
          const levelIndex = i;
          logger[levelName] = function() {
            // can't use arrow function with "arguments"
            write(levelIndex, levelName, arguments);
          };
        }
      }
    }

    return logger;
  }

  function validateLogger$1(logger) {
    logLevels.forEach(level => {
      if (level !== 'none' && (!logger[level] || typeof logger[level] !== 'function')) {
        throw new Error('Provided logger instance must support logger.' + level + '(...) method');
        // Note that the SDK normally does not throw exceptions to the application, but that rule
        // does not apply to LDClient.init() which will throw an exception if the parameters are so
        // invalid that we cannot proceed with creating the client. An invalid logger meets those
        // criteria since the SDK calls the logger during nearly all of its operations.
      }
    });
  }

  var loggers = {
    commonBasicLogger: commonBasicLogger$2,
    validateLogger: validateLogger$1,
  };

  function errorString(err) {
    if (err && err.message) {
      return err.message;
    }
    if (typeof err === 'string' || err instanceof String) {
      return err;
    }
    return JSON.stringify(err);
  }

  const clientInitialized = function() {
    return 'LaunchDarkly client initialized';
  };

  const docLink =
    ' Please see https://docs.launchdarkly.com/sdk/client-side/javascript#initializing-the-client for instructions on SDK initialization.';

  const clientNotReady = function() {
    return 'LaunchDarkly client is not ready';
  };

  const eventCapacityExceeded = function() {
    return 'Exceeded event queue capacity. Increase capacity to avoid dropping events.';
  };

  const eventWithoutContext = function() {
    return 'Be sure to call `identify` in the LaunchDarkly client: https://docs.launchdarkly.com/sdk/features/identify#javascript';
  };

  const invalidContentType = function(contentType) {
    return 'Expected application/json content type but got "' + contentType + '"';
  };

  const invalidKey = function() {
    return 'Event key must be a string';
  };

  const localStorageUnavailable = function(err) {
    return 'local storage is unavailable: ' + errorString(err);
  };

  const networkError = e => 'network error' + (e ? ' (' + e + ')' : '');

  // We should remove unknownCustomEventKey in the future - see comments in track() in index.js
  const unknownCustomEventKey = function(key) {
    return 'Custom event "' + key + '" does not exist';
  };

  const environmentNotFound = function() {
    return 'Environment not found. Double check that you specified a valid environment/client-side ID.' + docLink;
  };

  const environmentNotSpecified = function() {
    return 'No environment/client-side ID was specified.' + docLink;
  };

  const errorFetchingFlags = function(err) {
    return 'Error fetching flag settings: ' + errorString(err);
  };

  const contextNotSpecified = function() {
    return 'No context specified.' + docLink;
  };

  const invalidContext = function() {
    return 'Invalid context specified.' + docLink;
  };

  const invalidData = function() {
    return 'Invalid data received from LaunchDarkly; connection may have been interrupted';
  };

  const bootstrapOldFormat = function() {
    return (
      'LaunchDarkly client was initialized with bootstrap data that did not include flag metadata. ' +
      'Events may not be sent correctly.' +
      docLink
    );
  };

  const bootstrapInvalid = function() {
    return 'LaunchDarkly bootstrap data is not available because the back end could not read the flags.';
  };

  const deprecated = function(oldName, newName) {
    if (newName) {
      return '"' + oldName + '" is deprecated, please use "' + newName + '"';
    }
    return '"' + oldName + '" is deprecated';
  };

  const httpErrorMessage = function(status, context, retryMessage) {
    return (
      'Received error ' +
      status +
      (status === 401 ? ' (invalid SDK key)' : '') +
      ' for ' +
      context +
      ' - ' +
      (errors.isHttpErrorRecoverable(status) ? retryMessage : 'giving up permanently')
    );
  };

  const httpUnavailable = function() {
    return 'Cannot make HTTP requests in this environment.' + docLink;
  };

  const identifyDisabled = function() {
    return 'identify() has no effect here; it must be called on the main client instance';
  };

  const streamClosing = function() {
    return 'Closing stream connection';
  };

  const streamConnecting = function(url) {
    return 'Opening stream connection to ' + url;
  };

  const streamError = function(err, streamReconnectDelay) {
    return (
      'Error on stream connection: ' +
      errorString(err) +
      ', will continue retrying every ' +
      streamReconnectDelay +
      ' milliseconds.'
    );
  };

  const unknownOption = name => 'Ignoring unknown config option "' + name + '"';

  const wrongOptionType = (name, expectedType, actualType) =>
    'Config option "' + name + '" should be of type ' + expectedType + ', got ' + actualType + ', using default value';

  const wrongOptionTypeBoolean = (name, actualType) =>
    'Config option "' + name + '" should be a boolean, got ' + actualType + ', converting to boolean';

  const optionBelowMinimum = (name, value, minimum) =>
    'Config option "' + name + '" was set to ' + value + ', changing to minimum value of ' + minimum;

  const debugPolling = function(url) {
    return 'polling for feature flags at ' + url;
  };

  const debugStreamPing = function() {
    return 'received ping message from stream';
  };

  const debugStreamPut = function() {
    return 'received streaming update for all flags';
  };

  const debugStreamPatch = function(key) {
    return 'received streaming update for flag "' + key + '"';
  };

  const debugStreamPatchIgnored = function(key) {
    return 'received streaming update for flag "' + key + '" but ignored due to version check';
  };

  const debugStreamDelete = function(key) {
    return 'received streaming deletion for flag "' + key + '"';
  };

  const debugStreamDeleteIgnored = function(key) {
    return 'received streaming deletion for flag "' + key + '" but ignored due to version check';
  };

  const debugEnqueueingEvent = function(kind) {
    return 'enqueueing "' + kind + '" event';
  };

  const debugPostingEvents = function(count) {
    return 'sending ' + count + ' events';
  };

  const debugPostingDiagnosticEvent = function(event) {
    return 'sending diagnostic event (' + event.kind + ')';
  };

  const invalidTagValue = name => `Config option "${name}" must only contain letters, numbers, ., _ or -.`;

  const tagValueTooLong = name => `Value of "${name}" was longer than 64 characters and was discarded.`;

  var messages = {
    bootstrapInvalid,
    bootstrapOldFormat,
    clientInitialized,
    clientNotReady,
    debugEnqueueingEvent,
    debugPostingDiagnosticEvent,
    debugPostingEvents,
    debugStreamDelete,
    debugStreamDeleteIgnored,
    debugStreamPatch,
    debugStreamPatchIgnored,
    debugStreamPing,
    debugPolling,
    debugStreamPut,
    deprecated,
    environmentNotFound,
    environmentNotSpecified,
    errorFetchingFlags,
    eventCapacityExceeded,
    eventWithoutContext,
    httpErrorMessage,
    httpUnavailable,
    identifyDisabled,
    invalidContentType,
    invalidData,
    invalidKey,
    invalidContext,
    invalidTagValue,
    localStorageUnavailable,
    networkError,
    optionBelowMinimum,
    streamClosing,
    streamConnecting,
    streamError,
    tagValueTooLong,
    unknownCustomEventKey,
    unknownOption,
    contextNotSpecified,
    wrongOptionType,
    wrongOptionTypeBoolean,
  };

  const { validateLogger } = loggers;



  // baseOptionDefs should contain an entry for each supported configuration option in the common package.
  // Each entry can have three properties:
  // - "default": the default value if any
  // - "type": a type constraint used if the type can't be inferred from the default value). The allowable
  //   values are "boolean", "string", "number", "array", "object", "function", or several of these OR'd
  //   together with "|" ("function|object").
  // - "minimum": minimum value if any for numeric properties
  //
  // The extraOptionDefs parameter to validate() uses the same format.
  const baseOptionDefs$1 = {
    baseUrl: { default: 'https://app.launchdarkly.com' },
    streamUrl: { default: 'https://clientstream.launchdarkly.com' },
    eventsUrl: { default: 'https://events.launchdarkly.com' },
    sendEvents: { default: true },
    streaming: { type: 'boolean' }, // default for this is undefined, which is different from false
    sendLDHeaders: { default: true },
    requestHeaderTransform: { type: 'function' },
    sendEventsOnlyForVariation: { default: false },
    useReport: { default: false },
    evaluationReasons: { default: false },
    eventCapacity: { default: 100, minimum: 1 },
    flushInterval: { default: 2000, minimum: 2000 },
    samplingInterval: { default: 0, minimum: 0 },
    streamReconnectDelay: { default: 1000, minimum: 0 },
    allAttributesPrivate: { default: false },
    privateAttributes: { default: [] },
    bootstrap: { type: 'string|object' },
    diagnosticRecordingInterval: { default: 900000, minimum: 2000 },
    diagnosticOptOut: { default: false },
    wrapperName: { type: 'string' },
    wrapperVersion: { type: 'string' },
    stateProvider: { type: 'object' }, // not a public option, used internally
    application: { validator: applicationConfigValidator },
  };

  /**
   * Expression to validate characters that are allowed in tag keys and values.
   */
  const allowedTagCharacters = /^(\w|\.|-)+$/;

  /**
   * Verify that a value meets the requirements for a tag value.
   * @param {string} tagValue
   * @param {Object} logger
   */
  function validateTagValue(name, tagValue, logger) {
    if (typeof tagValue !== 'string' || !tagValue.match(allowedTagCharacters)) {
      logger.warn(messages.invalidTagValue(name));
      return undefined;
    }
    if (tagValue.length > 64) {
      logger.warn(messages.tagValueTooLong(name));
      return undefined;
    }
    return tagValue;
  }

  function applicationConfigValidator(name, value, logger) {
    const validated = {};
    if (value.id) {
      validated.id = validateTagValue(`${name}.id`, value.id, logger);
    }
    if (value.version) {
      validated.version = validateTagValue(`${name}.version`, value.version, logger);
    }
    return validated;
  }

  function validate(options, emitter, extraOptionDefs, logger) {
    const optionDefs = utils.extend({ logger: { default: logger } }, baseOptionDefs$1, extraOptionDefs);

    const deprecatedOptions = {
      // As of the latest major version, there are no deprecated options. Next time we deprecate
      // something, add an item here where the property name is the deprecated name, and the
      // property value is the preferred name if any, or null/undefined if there is no replacement.
    };

    function checkDeprecatedOptions(config) {
      const opts = config;
      Object.keys(deprecatedOptions).forEach(oldName => {
        if (opts[oldName] !== undefined) {
          const newName = deprecatedOptions[oldName];
          logger && logger.warn(messages.deprecated(oldName, newName));
          if (newName) {
            if (opts[newName] === undefined) {
              opts[newName] = opts[oldName];
            }
            delete opts[oldName];
          }
        }
      });
    }

    function applyDefaults(config) {
      // This works differently from utils.extend() in that it *will not* override a default value
      // if the provided value is explicitly set to null. This provides backward compatibility
      // since in the past we only used the provided values if they were truthy.
      const ret = utils.extend({}, config);
      Object.keys(optionDefs).forEach(name => {
        if (ret[name] === undefined || ret[name] === null) {
          ret[name] = optionDefs[name] && optionDefs[name].default;
        }
      });
      return ret;
    }

    function validateTypesAndNames(config) {
      const ret = utils.extend({}, config);
      const typeDescForValue = value => {
        if (value === null) {
          return 'any';
        }
        if (value === undefined) {
          return undefined;
        }
        if (Array.isArray(value)) {
          return 'array';
        }
        const t = typeof value;
        if (t === 'boolean' || t === 'string' || t === 'number' || t === 'function') {
          return t;
        }
        return 'object';
      };
      Object.keys(config).forEach(name => {
        const value = config[name];
        if (value !== null && value !== undefined) {
          const optionDef = optionDefs[name];
          if (optionDef === undefined) {
            reportArgumentError(messages.unknownOption(name));
          } else {
            const expectedType = optionDef.type || typeDescForValue(optionDef.default);
            const validator = optionDef.validator;
            if (validator) {
              const validated = validator(name, config[name], logger);
              if (validated !== undefined) {
                ret[name] = validated;
              } else {
                delete ret[name];
              }
            } else if (expectedType !== 'any') {
              const allowedTypes = expectedType.split('|');
              const actualType = typeDescForValue(value);
              if (allowedTypes.indexOf(actualType) < 0) {
                if (expectedType === 'boolean') {
                  ret[name] = !!value;
                  reportArgumentError(messages.wrongOptionTypeBoolean(name, actualType));
                } else {
                  reportArgumentError(messages.wrongOptionType(name, expectedType, actualType));
                  ret[name] = optionDef.default;
                }
              } else {
                if (actualType === 'number' && optionDef.minimum !== undefined && value < optionDef.minimum) {
                  reportArgumentError(messages.optionBelowMinimum(name, value, optionDef.minimum));
                  ret[name] = optionDef.minimum;
                }
              }
            }
          }
        }
      });
      return ret;
    }

    function reportArgumentError(message) {
      utils.onNextTick(() => {
        emitter && emitter.maybeReportError(new errors.LDInvalidArgumentError(message));
      });
    }

    let config = utils.extend({}, options || {});

    checkDeprecatedOptions(config);

    config = applyDefaults(config);
    config = validateTypesAndNames(config);
    validateLogger(config.logger);

    return config;
  }

  /**
   * Get tags for the specified configuration.
   *
   * If any additional tags are added to the configuration, then the tags from
   * this method should be extended with those.
   * @param {Object} config The already valiated configuration.
   * @returns {Object} The tag configuration.
   */
  function getTags(config) {
    const tags = {};
    if (config) {
      if (config.application && config.application.id !== undefined && config.application.id !== null) {
        tags['application-id'] = [config.application.id];
      }
      if (config.application && config.application.version !== undefined && config.application.id !== null) {
        tags['application-version'] = [config.application.version];
      }
    }

    return tags;
  }

  var configuration = {
    baseOptionDefs: baseOptionDefs$1,
    validate,
    getTags,
  };

  const { getLDUserAgentString } = utils;


  function getLDHeaders$3(platform, options) {
    if (options && !options.sendLDHeaders) {
      return {};
    }
    const h = {};
    h[platform.userAgentHeaderName || 'User-Agent'] = getLDUserAgentString(platform);
    if (options && options.wrapperName) {
      h['X-LaunchDarkly-Wrapper'] = options.wrapperVersion
        ? options.wrapperName + '/' + options.wrapperVersion
        : options.wrapperName;
    }
    const tags = configuration.getTags(options);
    const tagKeys = Object.keys(tags);
    if (tagKeys.length) {
      h['x-launchdarkly-tags'] = tagKeys
        .sort()
        .flatMap(
          key => (Array.isArray(tags[key]) ? tags[key].sort().map(value => `${key}/${value}`) : [`${key}/${tags[key]}`])
        )
        .join(' ');
    }
    return h;
  }

  function transformHeaders$3(headers, options) {
    if (!options || !options.requestHeaderTransform) {
      return headers;
    }
    return options.requestHeaderTransform({ ...headers });
  }

  var headers = {
    getLDHeaders: getLDHeaders$3,
    transformHeaders: transformHeaders$3,
  };

  const { v1: uuidv1$2 } = esmBrowser;
  const { getLDHeaders: getLDHeaders$2, transformHeaders: transformHeaders$2 } = headers;

  const MAX_URL_LENGTH = 2000;

  function EventSender(platform, environmentId, options) {
    const imageUrlPath = '/a/' + environmentId + '.gif';
    const baseHeaders = utils.extend({ 'Content-Type': 'application/json' }, getLDHeaders$2(platform, options));
    const httpFallbackPing = platform.httpFallbackPing; // this will be set for us if we're in the browser SDK
    const sender = {};

    function getResponseInfo(result) {
      const ret = { status: result.status };
      const dateStr = result.header('date');
      if (dateStr) {
        const time = Date.parse(dateStr);
        if (time) {
          ret.serverTime = time;
        }
      }
      return ret;
    }

    sender.sendChunk = (events, url, isDiagnostic, usePost) => {
      const jsonBody = JSON.stringify(events);
      const payloadId = isDiagnostic ? null : uuidv1$2();

      function doPostRequest(canRetry) {
        const headers = isDiagnostic
          ? baseHeaders
          : utils.extend({}, baseHeaders, {
              'X-LaunchDarkly-Event-Schema': '3',
              'X-LaunchDarkly-Payload-ID': payloadId,
            });
        return platform
          .httpRequest('POST', url, transformHeaders$2(headers, options), jsonBody)
          .promise.then(result => {
            if (!result) {
              // This was a response from a fire-and-forget request, so we won't have a status.
              return;
            }
            if (result.status >= 400 && errors.isHttpErrorRecoverable(result.status) && canRetry) {
              return doPostRequest(false);
            } else {
              return getResponseInfo(result);
            }
          })
          .catch(() => {
            if (canRetry) {
              return doPostRequest(false);
            }
            return Promise.reject();
          });
      }

      if (usePost) {
        return doPostRequest(true).catch(() => {});
      } else {
        httpFallbackPing && httpFallbackPing(url + imageUrlPath + '?d=' + utils.base64URLEncode(jsonBody));
        return Promise.resolve(); // we don't wait for this request to complete, it's just a one-way ping
      }
    };

    sender.sendEvents = function(events, url, isDiagnostic) {
      if (!platform.httpRequest) {
        return Promise.resolve();
      }
      const canPost = platform.httpAllowsPost();
      let chunks;
      if (canPost) {
        // no need to break up events into chunks if we can send a POST
        chunks = [events];
      } else {
        chunks = utils.chunkEventsForUrl(MAX_URL_LENGTH - url.length, events);
      }
      const results = [];
      for (let i = 0; i < chunks.length; i++) {
        results.push(sender.sendChunk(chunks[i], url, isDiagnostic, canPost));
      }
      return Promise.all(results);
    };

    return sender;
  }

  var EventSender_1 = EventSender;

  function EventSummarizer() {
    const es = {};

    let startDate = 0,
      endDate = 0,
      counters = {};

    es.summarizeEvent = function(event) {
      if (event.kind === 'feature') {
        const counterKey =
          event.key +
          ':' +
          (event.variation !== null && event.variation !== undefined ? event.variation : '') +
          ':' +
          (event.version !== null && event.version !== undefined ? event.version : '');
        const counterVal = counters[counterKey];
        if (counterVal) {
          counterVal.count = counterVal.count + 1;
        } else {
          counters[counterKey] = {
            count: 1,
            key: event.key,
            variation: event.variation,
            version: event.version,
            value: event.value,
            default: event.default,
          };
        }
        if (startDate === 0 || event.creationDate < startDate) {
          startDate = event.creationDate;
        }
        if (event.creationDate > endDate) {
          endDate = event.creationDate;
        }
      }
    };

    es.getSummary = function() {
      const flagsOut = {};
      let empty = true;
      for (const i in counters) {
        const c = counters[i];
        let flag = flagsOut[c.key];
        if (!flag) {
          flag = {
            default: c.default,
            counters: [],
          };
          flagsOut[c.key] = flag;
        }
        const counterOut = {
          value: c.value,
          count: c.count,
        };
        if (c.variation !== undefined && c.variation !== null) {
          counterOut.variation = c.variation;
        }
        if (c.version) {
          counterOut.version = c.version;
        } else {
          counterOut.unknown = true;
        }
        flag.counters.push(counterOut);
        empty = false;
      }
      return empty
        ? null
        : {
            startDate,
            endDate,
            features: flagsOut,
          };
    };

    es.clearSummary = function() {
      startDate = 0;
      endDate = 0;
      counters = {};
    };

    return es;
  }

  var EventSummarizer_1 = EventSummarizer;

  /**
   * Take a key string and escape the characters to allow it to be used as a reference.
   * @param {string} key
   * @returns {string} The processed key.
   */
  function processEscapeCharacters(key) {
    return key.replace(/~/g, '~0').replace(/\//g, '~1');
  }

  /**
   * @param {string} reference The reference to get the components of.
   * @returns {string[]} The components of the reference. Escape characters will be converted to their representative values.
   */
  function getComponents(reference) {
    const referenceWithoutPrefix = reference.startsWith('/') ? reference.substring(1) : reference;
    return referenceWithoutPrefix
      .split('/')
      .map(component => (component.indexOf('~') >= 0 ? component.replace(/~1/g, '/').replace(/~0/g, '~') : component));
  }

  /**
   * @param {string} reference The reference to check if it is a literal.
   * @returns true if the reference is a literal.
   */
  function isLiteral(reference) {
    return !reference.startsWith('/');
  }

  /**
   * Compare two references and determine if they are equivalent.
   * @param {string} a
   * @param {string} b
   */
  function compare(a, b) {
    const aIsLiteral = isLiteral(a);
    const bIsLiteral = isLiteral(b);
    if (aIsLiteral && bIsLiteral) {
      return a === b;
    }
    if (aIsLiteral) {
      const bComponents = getComponents(b);
      if (bComponents.length !== 1) {
        return false;
      }
      return a === bComponents[0];
    }
    if (bIsLiteral) {
      const aComponents = getComponents(a);
      if (aComponents.length !== 1) {
        return false;
      }
      return b === aComponents[0];
    }
    return a === b;
  }

  /**
   * @param {string} a
   * @param {string} b
   * @returns The two strings joined by '/'.
   */
  function join(a, b) {
    return `${a}/${b}`;
  }

  /**
   * There are cases where a field could have been named with a preceeding '/'.
   * If that attribute was private, then the literal would appear to be a reference.
   * This method can be used to convert a literal to a reference in such situations.
   * @param {string} literal The literal to convert to a reference.
   * @returns A literal which has been converted to a reference.
   */
  function literalToReference(literal) {
    return `/${processEscapeCharacters(literal)}`;
  }

  /**
   * Clone an object excluding the values referenced by a list of references.
   * @param {Object} target The object to clone.
   * @param {string[]} references A list of references from the cloned object.
   * @returns {{cloned: Object, excluded: string[]}} The cloned object and a list of excluded values.
   */
  function cloneExcluding(target, references) {
    const stack = [];
    const cloned = {};
    const excluded = [];

    stack.push(
      ...Object.keys(target).map(key => ({
        key,
        ptr: literalToReference(key),
        source: target,
        parent: cloned,
        visited: [target],
      }))
    );

    while (stack.length) {
      const item = stack.pop();
      if (!references.some(ptr => compare(ptr, item.ptr))) {
        const value = item.source[item.key];

        // Handle null because it overlaps with object, which we will want to handle later.
        if (value === null) {
          item.parent[item.key] = value;
        } else if (Array.isArray(value)) {
          item.parent[item.key] = [...value];
        } else if (typeof value === 'object') {
          //Arrays and null must already be handled.

          //Prevent cycles by not visiting the same object
          //with in the same branch. Parallel branches
          //may contain the same object.
          if (item.visited.includes(value)) {
            continue;
          }

          item.parent[item.key] = {};

          stack.push(
            ...Object.keys(value).map(key => ({
              key,
              ptr: join(item.ptr, processEscapeCharacters(key)),
              source: value,
              parent: item.parent[item.key],
              visited: [...item.visited, value],
            }))
          );
        } else {
          item.parent[item.key] = value;
        }
      } else {
        excluded.push(item.ptr);
      }
    }
    return { cloned, excluded: excluded.sort() };
  }

  var attributeReference = {
    cloneExcluding,
    compare,
    literalToReference,
  };

  function ContextFilter(config) {
    const filter = {};

    const allAttributesPrivate = config.allAttributesPrivate;
    const privateAttributes = config.privateAttributes || [];

    // These attributes cannot be removed via a private attribute.
    const protectedAttributes = ['key', 'kind', '_meta', 'anonymous'];

    const legacyTopLevelCopyAttributes = ['name', 'ip', 'firstName', 'lastName', 'email', 'avatar', 'country'];

    /**
     * For the given context and configuration get a list of attributes to filter.
     * @param {Object} context
     * @returns {string[]} A list of the attributes to filter.
     */
    const getAttributesToFilter = context =>
      (allAttributesPrivate
        ? Object.keys(context)
        : [...privateAttributes, ...((context._meta && context._meta.privateAttributes) || [])]
      ).filter(attr => !protectedAttributes.some(protectedAttr => attributeReference.compare(attr, protectedAttr)));

    /**
     * @param {Object} context
     * @returns {Object} A copy of the context with private attributes removed,
     * and the redactedAttributes meta populated.
     */
    const filterSingleKind = context => {
      if (typeof context !== 'object' || context === null || Array.isArray(context)) {
        return undefined;
      }

      const { cloned, excluded } = attributeReference.cloneExcluding(context, getAttributesToFilter(context));
      cloned.key = String(cloned.key);
      if (excluded.length) {
        if (!cloned._meta) {
          cloned._meta = {};
        }
        cloned._meta.redactedAttributes = excluded;
      }
      if (cloned._meta) {
        if (cloned._meta.secondary === null) {
          delete cloned._meta.secondary;
        }
        if (cloned._meta.secondary !== undefined) {
          cloned._meta.secondary = String(cloned._meta.secondary);
        }
        delete cloned._meta['privateAttributes'];
        if (Object.keys(cloned._meta).length === 0) {
          delete cloned._meta;
        }
      }
      // Make sure anonymous is boolean if present.
      // Null counts as present, and would be falsy, which is the default.
      if (cloned.anonymous !== undefined) {
        cloned.anonymous = !!cloned.anonymous;
      }

      return cloned;
    };

    /**
     * @param {Object} context
     * @returns {Object} A copy of the context with the private attributes removed,
     * and the redactedAttributes meta populated for each sub-context.
     */
    const filterMultiKind = context => {
      const filtered = {
        kind: context.kind,
      };
      const contextKeys = Object.keys(context);

      for (const contextKey of contextKeys) {
        if (contextKey !== 'kind') {
          const filteredContext = filterSingleKind(context[contextKey]);
          if (filteredContext) {
            filtered[contextKey] = filteredContext;
          }
        }
      }
      return filtered;
    };

    /**
     * Convert the LDUser object into an LDContext object.
     * @param {Object} user The LDUser to produce an LDContext for.
     * @returns {Object} A single kind context based on the provided user.
     */
    const legacyToSingleKind = user => {
      const filtered = {
        /* Destructure custom items into the top level.
           Duplicate keys will be overridden by previously
           top level items.
        */
        ...(user.custom || {}),

        // Implicity a user kind.
        kind: 'user',

        key: user.key,
      };

      if (user.anonymous !== undefined) {
        filtered.anonymous = !!user.anonymous;
      }

      // Copy top level keys and convert them to strings.
      // Remove keys that may have been destructured from `custom`.
      for (const key of legacyTopLevelCopyAttributes) {
        delete filtered[key];
        if (user[key] !== undefined && user[key] !== null) {
          filtered[key] = String(user[key]);
        }
      }

      if (user.privateAttributeNames !== undefined && user.privateAttributeNames !== null) {
        filtered._meta = filtered._meta || {};
        // If any private attributes started with '/' we need to convert them to references, otherwise the '/' will
        // cause the literal to incorrectly be treated as a reference.
        filtered._meta.privateAttributes = user.privateAttributeNames.map(
          literal => (literal.startsWith('/') ? attributeReference.literalToReference(literal) : literal)
        );
      }
      if (user.secondary !== undefined && user.secondary !== null) {
        filtered._meta = filtered._meta || {};
        filtered._meta.secondary = String(user.secondary);
      }

      return filtered;
    };

    filter.filter = context => {
      if (context.kind === undefined || context.kind === null) {
        return filterSingleKind(legacyToSingleKind(context));
      } else if (context.kind === 'multi') {
        return filterMultiKind(context);
      } else {
        return filterSingleKind(context);
      }
    };

    return filter;
  }

  var ContextFilter_1 = ContextFilter;

  function EventProcessor(
    platform,
    options,
    environmentId,
    diagnosticsAccumulator = null,
    emitter = null,
    sender = null
  ) {
    const processor = {};
    const eventSender = sender || EventSender_1(platform, environmentId, options);
    const mainEventsUrl = utils.appendUrlPath(options.eventsUrl, '/events/bulk/' + environmentId);
    const summarizer = EventSummarizer_1();
    const contextFilter = ContextFilter_1(options);
    const samplingInterval = options.samplingInterval;
    const eventCapacity = options.eventCapacity;
    const flushInterval = options.flushInterval;
    const logger = options.logger;
    let queue = [];
    let lastKnownPastTime = 0;
    let disabled = false;
    let exceededCapacity = false;
    let flushTimer;

    function shouldSampleEvent() {
      return samplingInterval === 0 || Math.floor(Math.random() * samplingInterval) === 0;
    }

    function shouldDebugEvent(e) {
      if (e.debugEventsUntilDate) {
        // The "last known past time" comes from the last HTTP response we got from the server.
        // In case the client's time is set wrong, at least we know that any expiration date
        // earlier than that point is definitely in the past.  If there's any discrepancy, we
        // want to err on the side of cutting off event debugging sooner.
        return e.debugEventsUntilDate > lastKnownPastTime && e.debugEventsUntilDate > new Date().getTime();
      }
      return false;
    }

    // Transform an event from its internal format to the format we use when sending a payload.
    function makeOutputEvent(e) {
      const ret = utils.extend({}, e);
      if (e.kind === 'identify') {
        // identify events always have an inline context
        ret.context = contextFilter.filter(e.context);
      } else {
        ret.contextKeys = getContextKeys(e);
        delete ret['context'];
      }
      if (e.kind === 'feature') {
        delete ret['trackEvents'];
        delete ret['debugEventsUntilDate'];
      }
      return ret;
    }

    function getContextKeys(event) {
      const keys = {};
      const context = event.context;
      if (context !== undefined) {
        if (context.kind === undefined) {
          keys.user = String(context.key);
        } else if (context.kind === 'multi') {
          Object.entries(context)
            .filter(([key]) => key !== 'kind')
            .forEach(([key, value]) => {
              if (value !== undefined && value.key !== undefined) {
                keys[key] = value.key;
              }
            });
        } else {
          keys[context.kind] = String(context.key);
        }
        return keys;
      }
      return undefined;
    }

    function addToOutbox(event) {
      if (queue.length < eventCapacity) {
        queue.push(event);
        exceededCapacity = false;
      } else {
        if (!exceededCapacity) {
          exceededCapacity = true;
          logger.warn(messages.eventCapacityExceeded());
        }
        if (diagnosticsAccumulator) {
          // For diagnostic events, we track how many times we had to drop an event due to exceeding the capacity.
          diagnosticsAccumulator.incrementDroppedEvents();
        }
      }
    }

    processor.enqueue = function(event) {
      if (disabled) {
        return;
      }
      let addFullEvent = false;
      let addDebugEvent = false;

      // Add event to the summary counters if appropriate
      summarizer.summarizeEvent(event);

      // Decide whether to add the event to the payload. Feature events may be added twice, once for
      // the event (if tracked) and once for debugging.
      if (event.kind === 'feature') {
        if (shouldSampleEvent()) {
          addFullEvent = !!event.trackEvents;
          addDebugEvent = shouldDebugEvent(event);
        }
      } else {
        addFullEvent = shouldSampleEvent();
      }

      if (addFullEvent) {
        addToOutbox(makeOutputEvent(event));
      }
      if (addDebugEvent) {
        const debugEvent = utils.extend({}, event, { kind: 'debug' });
        debugEvent.context = contextFilter.filter(debugEvent.context);
        delete debugEvent['trackEvents'];
        delete debugEvent['debugEventsUntilDate'];
        addToOutbox(debugEvent);
      }
    };

    processor.flush = function() {
      if (disabled) {
        return Promise.resolve();
      }
      const eventsToSend = queue;
      const summary = summarizer.getSummary();
      summarizer.clearSummary();
      if (summary) {
        summary.kind = 'summary';
        eventsToSend.push(summary);
      }
      if (diagnosticsAccumulator) {
        // For diagnostic events, we record how many events were in the queue at the last flush (since "how
        // many events happened to be in the queue at the moment we decided to send a diagnostic event" would
        // not be a very useful statistic).
        diagnosticsAccumulator.setEventsInLastBatch(eventsToSend.length);
      }
      if (eventsToSend.length === 0) {
        return Promise.resolve();
      }
      queue = [];
      logger.debug(messages.debugPostingEvents(eventsToSend.length));
      return eventSender.sendEvents(eventsToSend, mainEventsUrl).then(responseInfo => {
        if (responseInfo) {
          if (responseInfo.serverTime) {
            lastKnownPastTime = responseInfo.serverTime;
          }
          if (!errors.isHttpErrorRecoverable(responseInfo.status)) {
            disabled = true;
          }
          if (responseInfo.status >= 400) {
            utils.onNextTick(() => {
              emitter.maybeReportError(
                new errors.LDUnexpectedResponseError(
                  messages.httpErrorMessage(responseInfo.status, 'event posting', 'some events were dropped')
                )
              );
            });
          }
        }
      });
    };

    processor.start = function() {
      const flushTick = () => {
        processor.flush();
        flushTimer = setTimeout(flushTick, flushInterval);
      };
      flushTimer = setTimeout(flushTick, flushInterval);
    };

    processor.stop = function() {
      clearTimeout(flushTimer);
    };

    return processor;
  }

  var EventProcessor_1 = EventProcessor;

  function EventEmitter(logger) {
    const emitter = {};
    const events = {};

    const listeningTo = event => !!events[event];

    emitter.on = function(event, handler, context) {
      events[event] = events[event] || [];
      events[event] = events[event].concat({
        handler: handler,
        context: context,
      });
    };

    emitter.off = function(event, handler, context) {
      if (!events[event]) {
        return;
      }
      for (let i = 0; i < events[event].length; i++) {
        if (events[event][i].handler === handler && events[event][i].context === context) {
          events[event] = events[event].slice(0, i).concat(events[event].slice(i + 1));
        }
      }
    };

    emitter.emit = function(event) {
      if (!events[event]) {
        return;
      }
      // Copy the list of handlers before iterating, in case any handler adds or removes another handler.
      // Any such changes should not affect what we do here-- we want to notify every handler that existed
      // at the moment that the event was fired.
      const copiedHandlers = events[event].slice(0);
      for (let i = 0; i < copiedHandlers.length; i++) {
        copiedHandlers[i].handler.apply(copiedHandlers[i].context, Array.prototype.slice.call(arguments, 1));
      }
    };

    emitter.getEvents = function() {
      return Object.keys(events);
    };

    emitter.getEventListenerCount = function(event) {
      return events[event] ? events[event].length : 0;
    };

    emitter.maybeReportError = function(error) {
      if (!error) {
        return;
      }
      if (listeningTo('error')) {
        this.emit('error', error);
      } else {
        (logger || console).error(error.message);
      }
    };
    return emitter;
  }

  var EventEmitter_1 = EventEmitter;

  // This file provides an abstraction of the client's startup state.
  //
  // Startup can either succeed or fail exactly once; calling signalSuccess() or signalFailure()
  // after that point has no effect.
  //
  // On success, we fire both an "initialized" event and a "ready" event. Both the waitForInitialization()
  // promise and the waitUntilReady() promise are resolved in this case.
  //
  // On failure, we fire both a "failed" event (with the error as a parameter) and a "ready" event.
  // The waitForInitialization() promise is rejected, but the waitUntilReady() promise is resolved.
  //
  // To complicate things, we must *not* create the waitForInitialization() promise unless it is
  // requested, because otherwise failures would cause an *unhandled* rejection which can be a
  // serious problem in some environments. So we use a somewhat roundabout system for tracking the
  // initialization state and lazily creating this promise.

  const readyEvent = 'ready',
    successEvent = 'initialized',
    failureEvent = 'failed';

  function InitializationStateTracker(eventEmitter) {
    let succeeded = false,
      failed = false,
      failureValue = null,
      initializationPromise = null;

    const readyPromise = new Promise(resolve => {
      const onReady = () => {
        eventEmitter.off(readyEvent, onReady); // we can't use "once" because it's not available on some JS platforms
        resolve();
      };
      eventEmitter.on(readyEvent, onReady);
    }).catch(() => {}); // this Promise should never be rejected, but the catch handler is a safety measure

    return {
      getInitializationPromise: () => {
        if (initializationPromise) {
          return initializationPromise;
        }
        if (succeeded) {
          return Promise.resolve();
        }
        if (failed) {
          return Promise.reject(failureValue);
        }
        initializationPromise = new Promise((resolve, reject) => {
          const onSuccess = () => {
            eventEmitter.off(successEvent, onSuccess);
            resolve();
          };
          const onFailure = err => {
            eventEmitter.off(failureEvent, onFailure);
            reject(err);
          };
          eventEmitter.on(successEvent, onSuccess);
          eventEmitter.on(failureEvent, onFailure);
        });
        return initializationPromise;
      },

      getReadyPromise: () => readyPromise,

      signalSuccess: () => {
        if (!succeeded && !failed) {
          succeeded = true;
          eventEmitter.emit(successEvent);
          eventEmitter.emit(readyEvent);
        }
      },

      signalFailure: err => {
        if (!succeeded && !failed) {
          failed = true;
          failureValue = err;
          eventEmitter.emit(failureEvent, err);
          eventEmitter.emit(readyEvent);
        }
        eventEmitter.maybeReportError(err); // the "error" event can be emitted more than once, unlike the others
      },
    };
  }

  var InitializationState = InitializationStateTracker;

  function PersistentFlagStore(storage, environment, hash, ident) {
    const store = {};

    function getFlagsKey() {
      let key = '';
      const context = ident.getContext();
      if (context) {
        key = hash || utils.btoa(JSON.stringify(context));
      }
      return 'ld:' + environment + ':' + key;
    }

    // Returns a Promise which will be resolved with a parsed JSON value if a stored value was available,
    // or resolved with null if there was no value or if storage was not available.
    store.loadFlags = () =>
      storage.get(getFlagsKey()).then(dataStr => {
        if (dataStr === null || dataStr === undefined) {
          return null;
        }
        try {
          let data = JSON.parse(dataStr);
          if (data) {
            const schema = data.$schema;
            if (schema === undefined || schema < 1) {
              data = utils.transformValuesToVersionedValues(data);
            } else {
              delete data['$schema'];
            }
          }
          return data;
        } catch (ex) {
          return store.clearFlags().then(() => null);
        }
      });

    // Resolves with true if successful, or false if storage is unavailable. Never rejects.
    store.saveFlags = flags => {
      const data = utils.extend({}, flags, { $schema: 1 });
      return storage.set(getFlagsKey(), JSON.stringify(data));
    };

    // Resolves with true if successful, or false if storage is unavailable. Never rejects.
    store.clearFlags = () => storage.clear(getFlagsKey());

    return store;
  }

  var PersistentFlagStore_1 = PersistentFlagStore;

  // The localStorageProvider is provided by the platform object. It should have the following
  // methods, each of which should return a Promise:
  // - get(key): Gets the string value, if any, for the given key
  // - set(key, value): Stores a string value for the given key
  // - remove(key): Removes the given key
  //
  // Storage is just a light wrapper of the localStorageProvider, adding error handling and
  // ensuring that we don't call it if it's unavailable. The get method will simply resolve
  // with an undefined value if there is an error or if there is no localStorageProvider.
  // None of the promises returned by Storage will ever be rejected.
  //
  // It is always possible that the underlying platform storage mechanism might fail or be
  // disabled. If so, it's likely that it will keep failing, so we will only log one warning
  // instead of repetitive warnings.
  function PersistentStorage(localStorageProvider, logger) {
    const storage = {};
    let loggedError = false;

    const logError = err => {
      if (!loggedError) {
        loggedError = true;
        logger.warn(messages.localStorageUnavailable(err));
      }
    };

    storage.isEnabled = () => !!localStorageProvider;

    // Resolves with a value, or undefined if storage is unavailable. Never rejects.
    storage.get = key =>
      new Promise(resolve => {
        if (!localStorageProvider) {
          resolve(undefined);
          return;
        }
        localStorageProvider
          .get(key)
          .then(resolve)
          .catch(err => {
            logError(err);
            resolve(undefined);
          });
      });

    // Resolves with true if successful, or false if storage is unavailable. Never rejects.
    storage.set = (key, value) =>
      new Promise(resolve => {
        if (!localStorageProvider) {
          resolve(false);
          return;
        }
        localStorageProvider
          .set(key, value)
          .then(() => resolve(true))
          .catch(err => {
            logError(err);
            resolve(false);
          });
      });

    // Resolves with true if successful, or false if storage is unavailable. Never rejects.
    storage.clear = key =>
      new Promise(resolve => {
        if (!localStorageProvider) {
          resolve(false);
          return;
        }
        localStorageProvider
          .clear(key)
          .then(() => resolve(true))
          .catch(err => {
            logError(err);
            resolve(false);
          });
      });

    return storage;
  }

  var PersistentStorage_1 = PersistentStorage;

  const { appendUrlPath: appendUrlPath$1, base64URLEncode, objectHasOwnProperty } = utils;
  const { getLDHeaders: getLDHeaders$1, transformHeaders: transformHeaders$1 } = headers;

  // The underlying event source implementation is abstracted via the platform object, which should
  // have these three properties:
  // eventSourceFactory(): a function that takes a URL and optional config object and returns an object
  //   with the same methods as the regular HTML5 EventSource object. The properties in the config
  //   object are those supported by the launchdarkly-eventsource package; browser EventSource
  //   implementations don't have any config options.
  // eventSourceIsActive(): a function that takes an EventSource-compatible object and returns true if
  //   it is in an active state (connected or connecting).
  // eventSourceAllowsReport: true if REPORT is supported.

  // The read timeout for the stream is a fixed value that is set to be slightly longer than the expected
  // interval between heartbeats from the LaunchDarkly streaming server. If this amount of time elapses
  // with no new data, the connection will be cycled.
  const streamReadTimeoutMillis = 5 * 60 * 1000; // 5 minutes

  function Stream(platform, config, environment, diagnosticsAccumulator) {
    const baseUrl = config.streamUrl;
    const logger = config.logger;
    const stream = {};
    const evalUrlPrefix = appendUrlPath$1(baseUrl, '/eval/' + environment);
    const useReport = config.useReport;
    const withReasons = config.evaluationReasons;
    const streamReconnectDelay = config.streamReconnectDelay;
    const headers = getLDHeaders$1(platform, config);
    let firstConnectionErrorLogged = false;
    let es = null;
    let reconnectTimeoutReference = null;
    let connectionAttemptStartTime;
    let context = null;
    let hash = null;
    let handlers = null;

    stream.connect = function(newContext, newHash, newHandlers) {
      context = newContext;
      hash = newHash;
      handlers = {};
      for (const key in newHandlers || {}) {
        handlers[key] = function(e) {
          // Reset the state for logging the first connection error so that the first
          // connection error following a successful connection will once again be logged.
          // We will decorate *all* handlers to do this to keep this abstraction agnostic
          // for different stream implementations.
          firstConnectionErrorLogged = false;
          logConnectionResult(true);
          newHandlers[key] && newHandlers[key](e);
        };
      }
      tryConnect();
    };

    stream.disconnect = function() {
      clearTimeout(reconnectTimeoutReference);
      reconnectTimeoutReference = null;
      closeConnection();
    };

    stream.isConnected = function() {
      return !!(es && platform.eventSourceIsActive && platform.eventSourceIsActive(es));
    };

    function handleError(err) {
      if (!firstConnectionErrorLogged) {
        logger.warn(messages.streamError(err, streamReconnectDelay));
        firstConnectionErrorLogged = true;
      }
      logConnectionResult(false);
      closeConnection();
      tryConnect(streamReconnectDelay);
    }

    function tryConnect(delay) {
      if (!reconnectTimeoutReference) {
        if (delay) {
          reconnectTimeoutReference = setTimeout(openConnection, delay);
        } else {
          openConnection();
        }
      }
    }

    function openConnection() {
      reconnectTimeoutReference = null;
      let url;
      let query = '';
      const options = { headers, readTimeoutMillis: streamReadTimeoutMillis };
      if (platform.eventSourceFactory) {
        if (hash !== null && hash !== undefined) {
          query = 'h=' + hash;
        }
        if (useReport) {
          if (platform.eventSourceAllowsReport) {
            url = evalUrlPrefix;
            options.method = 'REPORT';
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(context);
          } else {
            // if we can't do REPORT, fall back to the old ping-based stream
            url = appendUrlPath$1(baseUrl, '/ping/' + environment);
            query = '';
          }
        } else {
          url = evalUrlPrefix + '/' + base64URLEncode(JSON.stringify(context));
        }
        options.headers = transformHeaders$1(options.headers, config);
        if (withReasons) {
          query = query + (query ? '&' : '') + 'withReasons=true';
        }
        url = url + (query ? '?' : '') + query;

        closeConnection();
        logger.info(messages.streamConnecting(url));
        logConnectionStarted();

        es = platform.eventSourceFactory(url, options);
        for (const key in handlers) {
          if (objectHasOwnProperty(handlers, key)) {
            es.addEventListener(key, handlers[key]);
          }
        }

        es.onerror = handleError;
      }
    }

    function closeConnection() {
      if (es) {
        logger.info(messages.streamClosing());
        es.close();
        es = null;
      }
    }

    function logConnectionStarted() {
      connectionAttemptStartTime = new Date().getTime();
    }

    function logConnectionResult(success) {
      if (connectionAttemptStartTime && diagnosticsAccumulator) {
        diagnosticsAccumulator.recordStreamInit(
          connectionAttemptStartTime,
          !success,
          new Date().getTime() - connectionAttemptStartTime
        );
      }
      connectionAttemptStartTime = null;
    }

    return stream;
  }

  var Stream_1 = Stream;

  // This function allows a series of Promises to be coalesced such that only the most recently
  // added one actually matters. For instance, if several HTTP requests are made to the same
  // endpoint and we want to ensure that whoever made each one always gets the latest data, each
  // can be passed to addPromise (on the same coalescer) and each caller can wait on the
  // coalescer.resultPromise; all three will then receive the result (or error) from the *last*
  // request, and the results of the first two will be discarded.
  //
  // The cancelFn callback, if present, will be called whenever an existing promise is being
  // discarded. This can be used for instance to abort an HTTP request that's now obsolete.
  //
  // The finallyFn callback, if present, is called on completion of the whole thing. This is
  // different from calling coalescer.resultPromise.finally() because it is executed before any
  // other handlers. Its purpose is to tell the caller that this coalescer should no longer be used.

  function promiseCoalescer(finallyFn) {
    let currentPromise;
    let currentCancelFn;
    let finalResolve;
    let finalReject;

    const coalescer = {};

    coalescer.addPromise = (p, cancelFn) => {
      currentPromise = p;
      currentCancelFn && currentCancelFn();
      currentCancelFn = cancelFn;

      p.then(
        result => {
          if (currentPromise === p) {
            finalResolve(result);
            finallyFn && finallyFn();
          }
        },
        error => {
          if (currentPromise === p) {
            finalReject(error);
            finallyFn && finallyFn();
          }
        }
      );
    };

    coalescer.resultPromise = new Promise((resolve, reject) => {
      finalResolve = resolve;
      finalReject = reject;
    });

    return coalescer;
  }

  var promiseCoalescer_1 = promiseCoalescer;

  const { transformHeaders, getLDHeaders } = headers;

  const jsonContentType = 'application/json';

  function getResponseError(result) {
    if (result.status === 404) {
      return new errors.LDInvalidEnvironmentIdError(messages.environmentNotFound());
    } else {
      return new errors.LDFlagFetchError(messages.errorFetchingFlags(result.statusText || String(result.status)));
    }
  }

  function Requestor(platform, options, environment) {
    const baseUrl = options.baseUrl;
    const useReport = options.useReport;
    const withReasons = options.evaluationReasons;
    const logger = options.logger;

    const requestor = {};

    const activeRequests = {}; // map of URLs to promiseCoalescers

    function fetchJSON(endpoint, body) {
      if (!platform.httpRequest) {
        return new Promise((resolve, reject) => {
          reject(new errors.LDFlagFetchError(messages.httpUnavailable()));
        });
      }

      const method = body ? 'REPORT' : 'GET';
      const headers = getLDHeaders(platform, options);
      if (body) {
        headers['Content-Type'] = jsonContentType;
      }

      let coalescer = activeRequests[endpoint];
      if (!coalescer) {
        coalescer = promiseCoalescer_1(() => {
          // this will be called once there are no more active requests for the same endpoint
          delete activeRequests[endpoint];
        });
        activeRequests[endpoint] = coalescer;
      }

      const req = platform.httpRequest(method, endpoint, transformHeaders(headers, options), body);
      const p = req.promise.then(
        result => {
          if (result.status === 200) {
            // We're using substring here because using startsWith would require a polyfill in IE.
            if (
              result.header('content-type') &&
              result.header('content-type').substring(0, jsonContentType.length) === jsonContentType
            ) {
              return JSON.parse(result.body);
            } else {
              const message = messages.invalidContentType(result.header('content-type') || '');
              return Promise.reject(new errors.LDFlagFetchError(message));
            }
          } else {
            return Promise.reject(getResponseError(result));
          }
        },
        e => Promise.reject(new errors.LDFlagFetchError(messages.networkError(e)))
      );
      coalescer.addPromise(p, () => {
        // this will be called if another request for the same endpoint supersedes this one
        req.cancel && req.cancel();
      });
      return coalescer.resultPromise;
    }

    // Performs a GET request to an arbitrary path under baseUrl. Returns a Promise which will resolve
    // with the parsed JSON response, or will be rejected if the request failed.
    requestor.fetchJSON = function(path) {
      return fetchJSON(utils.appendUrlPath(baseUrl, path), null);
    };

    // Requests the current state of all flags for the given context from LaunchDarkly. Returns a Promise
    // which will resolve with the parsed JSON response, or will be rejected if the request failed.
    requestor.fetchFlagSettings = function(context, hash) {
      let data;
      let endpoint;
      let query = '';
      let body;

      if (useReport) {
        endpoint = [baseUrl, '/sdk/evalx/', environment, '/user'].join('');
        body = JSON.stringify(context);
      } else {
        data = utils.base64URLEncode(JSON.stringify(context));
        endpoint = [baseUrl, '/sdk/evalx/', environment, '/users/', data].join('');
      }
      if (hash) {
        query = 'h=' + hash;
      }
      if (withReasons) {
        query = query + (query ? '&' : '') + 'withReasons=true';
      }
      endpoint = endpoint + (query ? '?' : '') + query;
      logger.debug(messages.debugPolling(endpoint));

      return fetchJSON(endpoint, body);
    };

    return requestor;
  }

  var Requestor_1 = Requestor;

  function Identity(initialContext, onChange) {
    const ident = {};
    let context;

    ident.setContext = function(c) {
      context = utils.sanitizeContext(c);
      if (context && onChange) {
        onChange(utils.clone(context));
      }
    };

    ident.getContext = function() {
      return context ? utils.clone(context) : null;
    };

    if (initialContext) {
      ident.setContext(initialContext);
    }

    return ident;
  }

  var Identity_1 = Identity;

  /**
   * Validate a context kind.
   * @param {string} kind
   * @returns true if the kind is valid.
   */
  function validKind(kind) {
    return typeof kind === 'string' && kind !== 'kind' && kind.match(/^(\w|\.|-)+$/);
  }

  /**
   * Perform a check of basic context requirements.
   * @param {Object} context
   * @param {boolean} allowLegacyKey If true, then a legacy user can have an
   * empty or non-string key. A legacy user is a context without a kind.
   * @returns true if the context meets basic requirements.
   */
  function checkContext$1(context, allowLegacyKey) {
    if (context) {
      if (allowLegacyKey && (context.kind === undefined || context.kind === null)) {
        return context.key !== undefined && context.key !== null;
      }
      const key = context.key;
      const kind = context.kind === undefined ? 'user' : context.kind;
      const kindValid = validKind(kind);
      const keyValid = kind === 'multi' || (key !== undefined && key !== null && key !== '');
      if (kind === 'multi') {
        const kinds = Object.keys(context).filter(key => key !== 'kind');
        return (
          keyValid &&
          kinds.every(key => validKind(key)) &&
          kinds.every(key => {
            const contextKey = context[key].key;
            return contextKey !== undefined && contextKey !== null && contextKey !== '';
          })
        );
      }
      return keyValid && kindValid;
    }
    return false;
  }

  /**
   * For a given context get a list of context kinds.
   * @param {Object} context
   * @returns A list of kinds in the context.
   */
  function getContextKinds$1(context) {
    if (context) {
      if (context.kind === null || context.kind === undefined) {
        return ['user'];
      }
      if (context.kind !== 'multi') {
        return [context.kind];
      }
      return Object.keys(context).filter(kind => kind !== 'kind');
    }
    return [];
  }

  /**
   * The partial URL encoding is needed because : is a valid character in context keys.
   *
   * Partial encoding is the replacement of all colon (:) characters with the URL
   * encoded equivalent (%3A) and all percent (%) characters with the URL encoded
   * equivalent (%25).
   * @param {string} key The key to encode.
   * @returns {string} Partially URL encoded key.
   */
  function encodeKey(key) {
    if (key.includes('%') || key.includes(':')) {
      return key.replace(/%/g, '%25').replace(/:/g, '%3A');
    }
    return key;
  }

  function getCanonicalKey(context) {
    if (context) {
      if ((context.kind === undefined || context.kind === null || context.kind === 'user') && context.key) {
        return context.key;
      } else if (context.kind !== 'multi' && context.key) {
        return `${context.kind}:${encodeKey(context.key)}`;
      } else if (context.kind === 'multi') {
        return Object.keys(context)
          .sort()
          .filter(key => key !== 'kind')
          .map(key => `${key}:${encodeKey(context[key].key)}`)
          .join(':');
      }
    }
  }

  var context = {
    checkContext: checkContext$1,
    getContextKinds: getContextKinds$1,
    getCanonicalKey,
  };

  const { v1: uuidv1$1 } = esmBrowser;
  const { getContextKinds } = context;





  const ldUserIdKey = 'ld:$anonUserId';

  /**
   * Create an object which can process a context and populate any required keys
   * for anonymous objects.
   *
   * @param {Object} persistentStorage The persistent storage from which to store
   * and access persisted anonymous context keys.
   * @returns An AnonymousContextProcessor.
   */
  function AnonymousContextProcessor(persistentStorage) {
    function getContextKeyIdString(kind) {
      if (kind === undefined || kind === null || kind === 'user') {
        return ldUserIdKey;
      }
      return `ld:$contextKey:${kind}`;
    }

    function getCachedContextKey(kind) {
      return persistentStorage.get(getContextKeyIdString(kind));
    }

    function setCachedContextKey(id, kind) {
      return persistentStorage.set(getContextKeyIdString(kind), id);
    }

    /**
     * Process a single kind context, or a single context within a multi-kind context.
     * @param {string} kind The kind of the context. Independent because the kind is not prevent
     * within a context in a multi-kind context.
     * @param {Object} context
     * @returns {Promise} a promise that resolves to a processed contexts, or rejects
     * a context which cannot be processed.
     */
    function processSingleKindContext(kind, context) {
      // We are working on a copy of an original context, so we want to re-assign
      // versus duplicating it again.

      /* eslint-disable no-param-reassign */
      if (context.key !== null && context.key !== undefined) {
        context.key = context.key.toString();
        return Promise.resolve(context);
      }

      if (context.anonymous) {
        // If the key doesn't exist, then the persistent storage will resolve
        // with undefined.
        return getCachedContextKey(kind).then(cachedId => {
          if (cachedId) {
            context.key = cachedId;
            return context;
          } else {
            const id = uuidv1$1();
            context.key = id;
            return setCachedContextKey(id, kind).then(() => context);
          }
        });
      } else {
        return Promise.reject(new errors.LDInvalidUserError(messages.invalidContext()));
      }
      /* eslint-enable no-param-reassign */
    }

    /**
     * Process the context, returning a Promise that resolves to the processed context, or rejects if there is an error.
     * @param {Object} context
     * @returns {Promise} A promise which resolves to a processed context, or a rejection if the context cannot be
     * processed. The context should still be checked for overall validity after being processed.
     */
    this.processContext = context => {
      if (!context) {
        return Promise.reject(new errors.LDInvalidUserError(messages.contextNotSpecified()));
      }

      const processedContext = utils.clone(context);

      if (context.kind === 'multi') {
        const kinds = getContextKinds(processedContext);

        return Promise.all(kinds.map(kind => processSingleKindContext(kind, processedContext[kind]))).then(
          () => processedContext
        );
      }
      return processSingleKindContext(context.kind, processedContext);
    };
  }

  var AnonymousContextProcessor_1 = AnonymousContextProcessor;

  const { v1: uuidv1 } = esmBrowser;
  // Note that in the diagnostic events spec, these IDs are to be generated with UUID v4. However,
  // in JS we were already using v1 for unique user keys, so to avoid bringing in two packages we
  // will use v1 here as well.

  const { baseOptionDefs } = configuration;

  const { appendUrlPath } = utils;

  function DiagnosticId(sdkKey) {
    const ret = {
      diagnosticId: uuidv1(),
    };
    if (sdkKey) {
      ret.sdkKeySuffix = sdkKey.length > 6 ? sdkKey.substring(sdkKey.length - 6) : sdkKey;
    }
    return ret;
  }

  // A stateful object holding statistics that will go into diagnostic events.

  function DiagnosticsAccumulator(startTime) {
    let dataSinceDate, droppedEvents, eventsInLastBatch, streamInits;

    function reset(time) {
      dataSinceDate = time;
      droppedEvents = 0;
      eventsInLastBatch = 0;
      streamInits = [];
    }

    reset(startTime);

    return {
      getProps: () => ({
        dataSinceDate,
        droppedEvents,
        eventsInLastBatch,
        streamInits,
        // omit deduplicatedUsers for the JS SDKs because they don't deduplicate users
      }),
      setProps: props => {
        dataSinceDate = props.dataSinceDate;
        droppedEvents = props.droppedEvents || 0;
        eventsInLastBatch = props.eventsInLastBatch || 0;
        streamInits = props.streamInits || [];
      },
      incrementDroppedEvents: () => {
        droppedEvents++;
      },
      setEventsInLastBatch: n => {
        eventsInLastBatch = n;
      },
      recordStreamInit: (timestamp, failed, durationMillis) => {
        const info = { timestamp, failed, durationMillis };
        streamInits.push(info);
      },
      reset,
    };
  }

  // An object that maintains information that will go into diagnostic events, and knows how to format
  // those events. It is instantiated by the SDK client, and shared with the event processor.
  //
  // The JS-based SDKs have two modes for diagnostic events. By default, the behavior is basically the
  // same as the server-side SDKs: a "diagnostic-init" event is sent on startup, and then "diagnostic"
  // events with operating statistics are sent periodically. However, in a browser environment this is
  // undesirable because the page may be reloaded frequently. In that case, setting the property
  // "platform.diagnosticUseCombinedEvent" to true enables an alternate mode in which a combination of
  // both kinds of event is sent at intervals, relative to the last time this was done (if any) which
  // is cached in local storage.

  function DiagnosticsManager(
    platform,
    persistentStorage,
    accumulator,
    eventSender,
    environmentId,
    config,
    diagnosticId
  ) {
    const combinedMode = !!platform.diagnosticUseCombinedEvent;
    const localStorageKey = 'ld:' + environmentId + ':$diagnostics';
    const diagnosticEventsUrl = appendUrlPath(config.eventsUrl, '/events/diagnostic/' + environmentId);
    const periodicInterval = config.diagnosticRecordingInterval;
    const acc = accumulator;
    const initialEventSamplingInterval = 4; // used only in combined mode - see start()
    let streamingEnabled = !!config.streaming;
    let eventSentTime;
    let periodicTimer;
    const manager = {};

    function makeInitProperties() {
      return {
        sdk: makeSdkData(),
        configuration: makeConfigData(),
        platform: platform.diagnosticPlatformData,
      };
    }

    // Send a diagnostic event and do not wait for completion.
    function sendDiagnosticEvent(event) {
      config.logger && config.logger.debug(messages.debugPostingDiagnosticEvent(event));
      eventSender
        .sendEvents(event, diagnosticEventsUrl, true)
        .then(() => undefined)
        .catch(() => undefined);
    }

    function loadProperties(callback) {
      if (!persistentStorage.isEnabled()) {
        return callback(false); // false indicates that local storage is not available
      }
      persistentStorage
        .get(localStorageKey)
        .then(data => {
          if (data) {
            try {
              const props = JSON.parse(data);
              acc.setProps(props);
              eventSentTime = props.dataSinceDate;
            } catch (e) {
              // disregard malformed cached data
            }
          }
          callback(true);
        })
        .catch(() => {
          callback(false);
        });
    }

    function saveProperties() {
      if (persistentStorage.isEnabled()) {
        const props = { ...acc.getProps() };
        persistentStorage.set(localStorageKey, JSON.stringify(props));
      }
    }

    // Creates the initial event that is sent by the event processor when the SDK starts up. This will not
    // be repeated during the lifetime of the SDK client. In combined mode, we don't send this.
    function createInitEvent() {
      return {
        kind: 'diagnostic-init',
        id: diagnosticId,
        creationDate: acc.getProps().dataSinceDate,
        ...makeInitProperties(),
      };
    }

    // Creates a periodic event containing time-dependent stats, and resets the state of the manager with
    // regard to those stats. In combined mode (browser SDK) this also contains the configuration data.
    function createPeriodicEventAndReset() {
      const currentTime = new Date().getTime();
      let ret = {
        kind: combinedMode ? 'diagnostic-combined' : 'diagnostic',
        id: diagnosticId,
        creationDate: currentTime,
        ...acc.getProps(),
      };
      if (combinedMode) {
        ret = { ...ret, ...makeInitProperties() };
      }
      acc.reset(currentTime);
      return ret;
    }

    function sendPeriodicEvent() {
      sendDiagnosticEvent(createPeriodicEventAndReset());
      periodicTimer = setTimeout(sendPeriodicEvent, periodicInterval);
      eventSentTime = new Date().getTime();
      if (combinedMode) {
        saveProperties();
      }
    }

    function makeSdkData() {
      const sdkData = { ...platform.diagnosticSdkData };
      if (config.wrapperName) {
        sdkData.wrapperName = config.wrapperName;
      }
      if (config.wrapperVersion) {
        sdkData.wrapperVersion = config.wrapperVersion;
      }
      return sdkData;
    }

    function makeConfigData() {
      const configData = {
        customBaseURI: config.baseUrl !== baseOptionDefs.baseUrl.default,
        customStreamURI: config.streamUrl !== baseOptionDefs.streamUrl.default,
        customEventsURI: config.eventsUrl !== baseOptionDefs.eventsUrl.default,
        eventsCapacity: config.eventCapacity,
        eventsFlushIntervalMillis: config.flushInterval,
        reconnectTimeMillis: config.streamReconnectDelay,
        streamingDisabled: !streamingEnabled,
        allAttributesPrivate: !!config.allAttributesPrivate,
        diagnosticRecordingIntervalMillis: config.diagnosticRecordingInterval,
        // The following extra properties are only provided by client-side JS SDKs:
        usingSecureMode: !!config.hash,
        bootstrapMode: !!config.bootstrap,
        fetchGoalsDisabled: !config.fetchGoals,
        sendEventsOnlyForVariation: !!config.sendEventsOnlyForVariation,
      };
      // Client-side JS SDKs do not have the following properties which other SDKs have:
      // connectTimeoutMillis
      // pollingIntervalMillis
      // samplingInterval
      // socketTimeoutMillis
      // startWaitMillis
      // userKeysCapacity
      // userKeysFlushIntervalMillis
      // usingProxy
      // usingProxyAuthenticator
      // usingRelayDaemon

      return configData;
    }

    // Called when the SDK is starting up. Either send an init event immediately, or, in the alternate
    // mode, check for cached local storage properties and send an event only if we haven't done so
    // recently.
    manager.start = () => {
      if (combinedMode) {
        loadProperties(localStorageAvailable => {
          if (localStorageAvailable) {
            const nextEventTime = (eventSentTime || 0) + periodicInterval;
            const timeNow = new Date().getTime();
            if (timeNow >= nextEventTime) {
              sendPeriodicEvent();
            } else {
              periodicTimer = setTimeout(sendPeriodicEvent, nextEventTime - timeNow);
            }
          } else {
            // We don't have the ability to cache anything in local storage, so we don't know if we
            // recently sent an event before this page load, but we would still prefer not to send one
            // on *every* page load. So, as a rough heuristic, we'll decide semi-randomly.
            if (Math.floor(Math.random() * initialEventSamplingInterval) === 0) {
              sendPeriodicEvent();
            } else {
              periodicTimer = setTimeout(sendPeriodicEvent, periodicInterval);
            }
          }
        });
      } else {
        sendDiagnosticEvent(createInitEvent());
        periodicTimer = setTimeout(sendPeriodicEvent, periodicInterval);
      }
    };

    manager.stop = () => {
      periodicTimer && clearTimeout(periodicTimer);
    };

    // Called when streaming mode is turned on or off dynamically.
    manager.setStreaming = enabled => {
      streamingEnabled = enabled;
    };

    return manager;
  }

  var diagnosticEvents = {
    DiagnosticId,
    DiagnosticsAccumulator,
    DiagnosticsManager,
  };

  const { commonBasicLogger: commonBasicLogger$1 } = loggers;



  const { checkContext } = context;

  const changeEvent = 'change';
  const internalChangeEvent = 'internal-change';

  // This is called by the per-platform initialize functions to create the base client object that we
  // may also extend with additional behavior. It returns an object with these properties:
  //   client: the actual client object
  //   options: the configuration (after any appropriate defaults have been applied)
  // If we need to give the platform-specific clients access to any internals here, we should add those
  // as properties of the return object, not public properties of the client.
  //
  // For definitions of the API in the platform object, see stubPlatform.js in the test code.

  function initialize$1(env, context, specifiedOptions, platform, extraOptionDefs) {
    const logger = createLogger();
    const emitter = EventEmitter_1(logger);
    const initializationStateTracker = InitializationState(emitter);
    const options = configuration.validate(specifiedOptions, emitter, extraOptionDefs, logger);
    const sendEvents = options.sendEvents;
    let environment = env;
    let hash = options.hash;

    const persistentStorage = PersistentStorage_1(platform.localStorage, logger);

    const eventSender = EventSender_1(platform, environment, options);

    const diagnosticsEnabled = options.sendEvents && !options.diagnosticOptOut;
    const diagnosticId = diagnosticsEnabled ? diagnosticEvents.DiagnosticId(environment) : null;
    const diagnosticsAccumulator = diagnosticsEnabled ? diagnosticEvents.DiagnosticsAccumulator(new Date().getTime()) : null;
    const diagnosticsManager = diagnosticsEnabled
      ? diagnosticEvents.DiagnosticsManager(
          platform,
          persistentStorage,
          diagnosticsAccumulator,
          eventSender,
          environment,
          options,
          diagnosticId
        )
      : null;

    const stream = Stream_1(platform, options, environment, diagnosticsAccumulator);

    const events =
      options.eventProcessor ||
      EventProcessor_1(platform, options, environment, diagnosticsAccumulator, emitter, eventSender);

    const requestor = Requestor_1(platform, options, environment);

    let flags = {};
    let useLocalStorage;
    let streamActive;
    let streamForcedState = options.streaming;
    let subscribedToChangeEvents;
    let inited = false;
    let closed = false;
    let firstEvent = true;

    // The "stateProvider" object is used in the Electron SDK, to allow one client instance to take partial
    // control of another. If present, it has the following contract:
    // - getInitialState() returns the initial client state if it is already available. The state is an
    //   object whose properties are "environment", "context", and "flags".
    // - on("init", listener) triggers an event when the initial client state becomes available, passing
    //   the state object to the listener.
    // - on("update", listener) triggers an event when flag values change and/or the current context changes.
    //   The parameter is an object that *may* contain "context" and/or "flags".
    // - enqueueEvent(event) accepts an analytics event object and returns true if the stateProvider will
    //   be responsible for delivering it, or false if we still should deliver it ourselves.
    const stateProvider = options.stateProvider;

    const ident = Identity_1(null, onIdentifyChange);
    const anonymousContextProcessor = new AnonymousContextProcessor_1(persistentStorage);
    const persistentFlagStore = persistentStorage.isEnabled()
      ? PersistentFlagStore_1(persistentStorage, environment, hash, ident)
      : null;

    function createLogger() {
      if (specifiedOptions && specifiedOptions.logger) {
        return specifiedOptions.logger;
      }
      return (extraOptionDefs && extraOptionDefs.logger && extraOptionDefs.logger.default) || commonBasicLogger$1('warn');
    }

    function readFlagsFromBootstrap(data) {
      // If the bootstrap data came from an older server-side SDK, we'll have just a map of keys to values.
      // Newer SDKs that have an allFlagsState method will provide an extra "$flagsState" key that contains
      // the rest of the metadata we want. We do it this way for backward compatibility with older JS SDKs.
      const keys = Object.keys(data);
      const metadataKey = '$flagsState';
      const validKey = '$valid';
      const metadata = data[metadataKey];
      if (!metadata && keys.length) {
        logger.warn(messages.bootstrapOldFormat());
      }
      if (data[validKey] === false) {
        logger.warn(messages.bootstrapInvalid());
      }
      const ret = {};
      keys.forEach(key => {
        if (key !== metadataKey && key !== validKey) {
          let flag = { value: data[key] };
          if (metadata && metadata[key]) {
            flag = utils.extend(flag, metadata[key]);
          } else {
            flag.version = 0;
          }
          ret[key] = flag;
        }
      });
      return ret;
    }

    function shouldEnqueueEvent() {
      return sendEvents && !closed && !platform.isDoNotTrack();
    }

    function enqueueEvent(event) {
      if (!environment) {
        // We're in paired mode and haven't been initialized with an environment or context yet
        return;
      }
      if (stateProvider && stateProvider.enqueueEvent && stateProvider.enqueueEvent(event)) {
        return; // it'll be handled elsewhere
      }

      if (!event.context) {
        if (firstEvent) {
          logger.warn(messages.eventWithoutContext());
          firstEvent = false;
        }
        return;
      }
      firstEvent = false;

      if (shouldEnqueueEvent()) {
        logger.debug(messages.debugEnqueueingEvent(event.kind));
        events.enqueue(event);
      }
    }

    function onIdentifyChange(context) {
      sendIdentifyEvent(context);
    }

    function sendIdentifyEvent(context) {
      if (stateProvider) {
        // In paired mode, the other client is responsible for sending identify events
        return;
      }
      if (context) {
        enqueueEvent({
          kind: 'identify',
          context,
          creationDate: new Date().getTime(),
        });
      }
    }

    function sendFlagEvent(key, detail, defaultValue, includeReason) {
      const context = ident.getContext();
      const now = new Date();
      const value = detail ? detail.value : null;

      const event = {
        kind: 'feature',
        key: key,
        context,
        value: value,
        variation: detail ? detail.variationIndex : null,
        default: defaultValue,
        creationDate: now.getTime(),
      };
      const flag = flags[key];
      if (flag) {
        event.version = flag.flagVersion ? flag.flagVersion : flag.version;
        event.trackEvents = flag.trackEvents;
        event.debugEventsUntilDate = flag.debugEventsUntilDate;
      }
      if ((includeReason || (flag && flag.trackReason)) && detail) {
        event.reason = detail.reason;
      }

      enqueueEvent(event);
    }

    function verifyContext(context) {
      // The context will already have been processed to have a string key, so we
      // do not need to allow for legacy keys in the check.
      if (checkContext(context, false)) {
        return Promise.resolve(context);
      } else {
        return Promise.reject(new errors.LDInvalidUserError(messages.invalidContext()));
      }
    }

    function identify(context, newHash, onDone) {
      if (closed) {
        return utils.wrapPromiseCallback(Promise.resolve({}), onDone);
      }
      if (stateProvider) {
        // We're being controlled by another client instance, so only that instance is allowed to change the context
        logger.warn(messages.identifyDisabled());
        return utils.wrapPromiseCallback(Promise.resolve(utils.transformVersionedValuesToValues(flags)), onDone);
      }
      const clearFirst = useLocalStorage && persistentFlagStore ? persistentFlagStore.clearFlags() : Promise.resolve();
      return utils.wrapPromiseCallback(
        clearFirst
          .then(() => anonymousContextProcessor.processContext(context))
          .then(verifyContext)
          .then(validatedContext =>
            requestor
              .fetchFlagSettings(validatedContext, newHash)
              // the following then() is nested within this one so we can use realUser from the previous closure
              .then(requestedFlags => {
                const flagValueMap = utils.transformVersionedValuesToValues(requestedFlags);
                ident.setContext(validatedContext);
                hash = newHash;
                if (requestedFlags) {
                  return replaceAllFlags(requestedFlags).then(() => flagValueMap);
                } else {
                  return flagValueMap;
                }
              })
          )
          .then(flagValueMap => {
            if (streamActive) {
              connectStream();
            }
            return flagValueMap;
          })
          .catch(err => {
            emitter.maybeReportError(err);
            return Promise.reject(err);
          }),
        onDone
      );
    }

    function getContext() {
      return ident.getContext();
    }

    function flush(onDone) {
      return utils.wrapPromiseCallback(sendEvents ? events.flush() : Promise.resolve(), onDone);
    }

    function variation(key, defaultValue) {
      return variationDetailInternal(key, defaultValue, true, false).value;
    }

    function variationDetail(key, defaultValue) {
      return variationDetailInternal(key, defaultValue, true, true);
    }

    function variationDetailInternal(key, defaultValue, sendEvent, includeReasonInEvent) {
      let detail;

      if (flags && utils.objectHasOwnProperty(flags, key) && flags[key] && !flags[key].deleted) {
        const flag = flags[key];
        detail = getFlagDetail(flag);
        if (flag.value === null || flag.value === undefined) {
          detail.value = defaultValue;
        }
      } else {
        detail = { value: defaultValue, variationIndex: null, reason: { kind: 'ERROR', errorKind: 'FLAG_NOT_FOUND' } };
      }

      if (sendEvent) {
        sendFlagEvent(key, detail, defaultValue, includeReasonInEvent);
      }

      return detail;
    }

    function getFlagDetail(flag) {
      return {
        value: flag.value,
        variationIndex: flag.variation === undefined ? null : flag.variation,
        reason: flag.reason || null,
      };
      // Note, the logic above ensures that variationIndex and reason will always be null rather than
      // undefined if we don't have values for them. That's just to avoid subtle errors that depend on
      // whether an object was JSON-encoded with null properties omitted or not.
    }

    function allFlags() {
      const results = {};

      if (!flags) {
        return results;
      }

      for (const key in flags) {
        if (utils.objectHasOwnProperty(flags, key) && !flags[key].deleted) {
          results[key] = variationDetailInternal(key, null, !options.sendEventsOnlyForVariation).value;
        }
      }

      return results;
    }

    function userContextKind(user) {
      return user.anonymous ? 'anonymousUser' : 'user';
    }

    function track(key, data, metricValue) {
      if (typeof key !== 'string') {
        emitter.maybeReportError(new errors.LDInvalidEventKeyError(messages.unknownCustomEventKey(key)));
        return;
      }

      // The following logic was used only for the JS browser SDK (js-client-sdk) and
      // is no longer needed as of version 2.9.13 of that SDK. The other client-side
      // JS-based SDKs did not define customEventFilter, and now none of them do. We
      // can remove this in the next major version of the common code, when it's OK to
      // make breaking changes to our internal API contracts.
      if (platform.customEventFilter && !platform.customEventFilter(key)) {
        logger.warn(messages.unknownCustomEventKey(key));
      }

      const context = ident.getContext();
      const e = {
        kind: 'custom',
        key: key,
        context,
        url: platform.getCurrentUrl(),
        creationDate: new Date().getTime(),
      };
      if (context && context.anonymous) {
        e.contextKind = userContextKind(context);
      }
      // Note, check specifically for null/undefined because it is legal to set these fields to a falsey value.
      if (data !== null && data !== undefined) {
        e.data = data;
      }
      if (metricValue !== null && metricValue !== undefined) {
        e.metricValue = metricValue;
      }
      enqueueEvent(e);
    }

    function connectStream() {
      streamActive = true;
      if (!ident.getContext()) {
        return;
      }
      const tryParseData = jsonData => {
        try {
          return JSON.parse(jsonData);
        } catch (err) {
          emitter.maybeReportError(new errors.LDInvalidDataError(messages.invalidData()));
          return undefined;
        }
      };
      stream.connect(ident.getContext(), hash, {
        ping: function() {
          logger.debug(messages.debugStreamPing());
          const contextAtTimeOfPingEvent = ident.getContext();
          requestor
            .fetchFlagSettings(contextAtTimeOfPingEvent, hash)
            .then(requestedFlags => {
              // Check whether the current context is still the same - we don't want to overwrite the flags if
              // the application has called identify() while this request was in progress
              if (utils.deepEquals(contextAtTimeOfPingEvent, ident.getContext())) {
                replaceAllFlags(requestedFlags || {});
              }
            })
            .catch(err => {
              emitter.maybeReportError(new errors.LDFlagFetchError(messages.errorFetchingFlags(err)));
            });
        },
        put: function(e) {
          const data = tryParseData(e.data);
          if (!data) {
            return;
          }
          logger.debug(messages.debugStreamPut());
          replaceAllFlags(data);
          // Don't wait for this Promise to be resolved; note that replaceAllFlags is guaranteed
          // never to have an unhandled rejection
        },
        patch: function(e) {
          const data = tryParseData(e.data);
          if (!data) {
            return;
          }
          // If both the flag and the patch have a version property, then the patch version must be
          // greater than the flag version for us to accept the patch.  If either one has no version
          // then the patch always succeeds.
          const oldFlag = flags[data.key];
          if (!oldFlag || !oldFlag.version || !data.version || oldFlag.version < data.version) {
            logger.debug(messages.debugStreamPatch(data.key));
            const mods = {};
            const newFlag = utils.extend({}, data);
            delete newFlag['key'];
            flags[data.key] = newFlag;
            const newDetail = getFlagDetail(newFlag);
            if (oldFlag) {
              mods[data.key] = { previous: oldFlag.value, current: newDetail };
            } else {
              mods[data.key] = { current: newDetail };
            }
            handleFlagChanges(mods); // don't wait for this Promise to be resolved
          } else {
            logger.debug(messages.debugStreamPatchIgnored(data.key));
          }
        },
        delete: function(e) {
          const data = tryParseData(e.data);
          if (!data) {
            return;
          }
          if (!flags[data.key] || flags[data.key].version < data.version) {
            logger.debug(messages.debugStreamDelete(data.key));
            const mods = {};
            if (flags[data.key] && !flags[data.key].deleted) {
              mods[data.key] = { previous: flags[data.key].value };
            }
            flags[data.key] = { version: data.version, deleted: true };
            handleFlagChanges(mods); // don't wait for this Promise to be resolved
          } else {
            logger.debug(messages.debugStreamDeleteIgnored(data.key));
          }
        },
      });
    }

    function disconnectStream() {
      if (streamActive) {
        stream.disconnect();
        streamActive = false;
      }
    }

    // Returns a Promise which will be resolved when we have completely updated the internal flags state,
    // dispatched all change events, and updated local storage if appropriate. This Promise is guaranteed
    // never to have an unhandled rejection.
    function replaceAllFlags(newFlags) {
      const changes = {};

      if (!newFlags) {
        return Promise.resolve();
      }

      for (const key in flags) {
        if (utils.objectHasOwnProperty(flags, key) && flags[key]) {
          if (newFlags[key] && !utils.deepEquals(newFlags[key].value, flags[key].value)) {
            changes[key] = { previous: flags[key].value, current: getFlagDetail(newFlags[key]) };
          } else if (!newFlags[key] || newFlags[key].deleted) {
            changes[key] = { previous: flags[key].value };
          }
        }
      }
      for (const key in newFlags) {
        if (utils.objectHasOwnProperty(newFlags, key) && newFlags[key] && (!flags[key] || flags[key].deleted)) {
          changes[key] = { current: getFlagDetail(newFlags[key]) };
        }
      }

      flags = { ...newFlags };
      return handleFlagChanges(changes).catch(() => {}); // swallow any exceptions from this Promise
    }

    // Returns a Promise which will be resolved when we have dispatched all change events and updated
    // local storage if appropriate.
    function handleFlagChanges(changes) {
      const keys = Object.keys(changes);

      if (keys.length > 0) {
        const changeEventParams = {};
        keys.forEach(key => {
          const current = changes[key].current;
          const value = current ? current.value : undefined;
          const previous = changes[key].previous;
          emitter.emit(changeEvent + ':' + key, value, previous);
          changeEventParams[key] = current ? { current: value, previous: previous } : { previous: previous };
        });

        emitter.emit(changeEvent, changeEventParams);
        emitter.emit(internalChangeEvent, flags);

        // By default, we send feature evaluation events whenever we have received new flag values -
        // the client has in effect evaluated these flags just by receiving them. This can be suppressed
        // by setting "sendEventsOnlyForVariation". Also, if we have a stateProvider, we don't send these
        // events because we assume they have already been sent by the other client that gave us the flags
        // (when it received them in the first place).
        if (!options.sendEventsOnlyForVariation && !stateProvider) {
          keys.forEach(key => {
            sendFlagEvent(key, changes[key].current);
          });
        }
      }

      if (useLocalStorage && persistentFlagStore) {
        return persistentFlagStore.saveFlags(flags);
      } else {
        return Promise.resolve();
      }
    }

    function on(event, handler, context) {
      if (isChangeEventKey(event)) {
        subscribedToChangeEvents = true;
        if (inited) {
          updateStreamingState();
        }
        emitter.on(event, handler, context);
      } else {
        emitter.on(...arguments);
      }
    }

    function off(event) {
      emitter.off(...arguments);
      if (isChangeEventKey(event)) {
        let haveListeners = false;
        emitter.getEvents().forEach(key => {
          if (isChangeEventKey(key) && emitter.getEventListenerCount(key) > 0) {
            haveListeners = true;
          }
        });
        if (!haveListeners) {
          subscribedToChangeEvents = false;
          if (streamActive && streamForcedState === undefined) {
            disconnectStream();
          }
        }
      }
    }

    function setStreaming(state) {
      const newState = state === null ? undefined : state;
      if (newState !== streamForcedState) {
        streamForcedState = newState;
        updateStreamingState();
      }
    }

    function updateStreamingState() {
      const shouldBeStreaming = streamForcedState || (subscribedToChangeEvents && streamForcedState === undefined);
      if (shouldBeStreaming && !streamActive) {
        connectStream();
      } else if (!shouldBeStreaming && streamActive) {
        disconnectStream();
      }
      if (diagnosticsManager) {
        diagnosticsManager.setStreaming(shouldBeStreaming);
      }
    }

    function isChangeEventKey(event) {
      return event === changeEvent || event.substr(0, changeEvent.length + 1) === changeEvent + ':';
    }

    if (typeof options.bootstrap === 'string' && options.bootstrap.toUpperCase() === 'LOCALSTORAGE') {
      if (persistentFlagStore) {
        useLocalStorage = true;
      } else {
        logger.warn(messages.localStorageUnavailable());
      }
    }

    if (typeof options.bootstrap === 'object') {
      // Set the flags as soon as possible before we get into any async code, so application code can read
      // them even if the ready event has not yet fired.
      flags = readFlagsFromBootstrap(options.bootstrap);
    }

    if (stateProvider) {
      // The stateProvider option is used in the Electron SDK, to allow a client instance in the main process
      // to control another client instance (i.e. this one) in the renderer process. We can't predict which
      // one will start up first, so the initial state may already be available for us or we may have to wait
      // to receive it.
      const state = stateProvider.getInitialState();
      if (state) {
        initFromStateProvider(state);
      } else {
        stateProvider.on('init', initFromStateProvider);
      }
      stateProvider.on('update', updateFromStateProvider);
    } else {
      finishInit().catch(signalFailedInit);
    }

    function finishInit() {
      if (!env) {
        return Promise.reject(new errors.LDInvalidEnvironmentIdError(messages.environmentNotSpecified()));
      }
      return anonymousContextProcessor
        .processContext(context)
        .then(verifyContext)
        .then(validatedContext => {
          ident.setContext(validatedContext);
          if (typeof options.bootstrap === 'object') {
            // flags have already been set earlier
            return signalSuccessfulInit();
          } else if (useLocalStorage) {
            return finishInitWithLocalStorage();
          } else {
            return finishInitWithPolling();
          }
        });
    }

    function finishInitWithLocalStorage() {
      return persistentFlagStore.loadFlags().then(storedFlags => {
        if (storedFlags === null || storedFlags === undefined) {
          flags = {};
          return requestor
            .fetchFlagSettings(ident.getContext(), hash)
            .then(requestedFlags => replaceAllFlags(requestedFlags || {}))
            .then(signalSuccessfulInit)
            .catch(err => {
              const initErr = new errors.LDFlagFetchError(messages.errorFetchingFlags(err));
              signalFailedInit(initErr);
            });
        } else {
          // We're reading the flags from local storage. Signal that we're ready,
          // then update localStorage for the next page load. We won't signal changes or update
          // the in-memory flags unless you subscribe for changes
          flags = storedFlags;
          utils.onNextTick(signalSuccessfulInit);

          return requestor
            .fetchFlagSettings(ident.getContext(), hash)
            .then(requestedFlags => replaceAllFlags(requestedFlags))
            .catch(err => emitter.maybeReportError(err));
        }
      });
    }

    function finishInitWithPolling() {
      return requestor
        .fetchFlagSettings(ident.getContext(), hash)
        .then(requestedFlags => {
          flags = requestedFlags || {};
          // Note, we don't need to call updateSettings here because local storage and change events are not relevant
          signalSuccessfulInit();
        })
        .catch(err => {
          flags = {};
          signalFailedInit(err);
        });
    }

    function initFromStateProvider(state) {
      environment = state.environment;
      ident.setContext(state.context);
      flags = { ...state.flags };
      utils.onNextTick(signalSuccessfulInit);
    }

    function updateFromStateProvider(state) {
      if (state.context) {
        ident.setContext(state.context);
      }
      if (state.flags) {
        replaceAllFlags(state.flags); // don't wait for this Promise to be resolved
      }
    }

    function signalSuccessfulInit() {
      logger.info(messages.clientInitialized());
      inited = true;
      updateStreamingState();
      initializationStateTracker.signalSuccess();
    }

    function signalFailedInit(err) {
      initializationStateTracker.signalFailure(err);
    }

    function start() {
      if (sendEvents) {
        if (diagnosticsManager) {
          diagnosticsManager.start();
        }
        events.start();
      }
    }

    function close(onDone) {
      if (closed) {
        return utils.wrapPromiseCallback(Promise.resolve(), onDone);
      }
      const finishClose = () => {
        closed = true;
        flags = {};
      };
      const p = Promise.resolve()
        .then(() => {
          disconnectStream();
          if (diagnosticsManager) {
            diagnosticsManager.stop();
          }
          if (sendEvents) {
            events.stop();
            return events.flush();
          }
        })
        .then(finishClose)
        .catch(finishClose);
      return utils.wrapPromiseCallback(p, onDone);
    }

    function getFlagsInternal() {
      // used by Electron integration
      return flags;
    }

    const client = {
      waitForInitialization: () => initializationStateTracker.getInitializationPromise(),
      waitUntilReady: () => initializationStateTracker.getReadyPromise(),
      identify: identify,
      getContext: getContext,
      variation: variation,
      variationDetail: variationDetail,
      track: track,
      on: on,
      off: off,
      setStreaming: setStreaming,
      flush: flush,
      allFlags: allFlags,
      close: close,
    };

    return {
      client: client, // The client object containing all public methods.
      options: options, // The validated configuration object, including all defaults.
      emitter: emitter, // The event emitter which can be used to log errors or trigger events.
      ident: ident, // The Identity object that manages the current context.
      logger: logger, // The logging abstraction.
      requestor: requestor, // The Requestor object.
      start: start, // Starts the client once the environment is ready.
      enqueueEvent: enqueueEvent, // Puts an analytics event in the queue, if event sending is enabled.
      getFlagsInternal: getFlagsInternal, // Returns flag data structure with all details.
      getEnvironmentId: () => environment, // Gets the environment ID (this may have changed since initialization, if we have a state provider)
      internalChangeEventName: internalChangeEvent, // This event is triggered whenever we have new flag state.
    };
  }

  var src = {
    initialize: initialize$1,
    commonBasicLogger: commonBasicLogger$1,
    errors,
    messages,
    utils,
  };
  var src_1 = src.initialize;
  var src_3 = src.errors;
  var src_4 = src.messages;

  function ownKeys(object, enumerableOnly) {
    var keys = Object.keys(object);

    if (Object.getOwnPropertySymbols) {
      var symbols = Object.getOwnPropertySymbols(object);
      enumerableOnly && (symbols = symbols.filter(function (sym) {
        return Object.getOwnPropertyDescriptor(object, sym).enumerable;
      })), keys.push.apply(keys, symbols);
    }

    return keys;
  }

  function _objectSpread2(target) {
    for (var i = 1; i < arguments.length; i++) {
      var source = null != arguments[i] ? arguments[i] : {};
      i % 2 ? ownKeys(Object(source), !0).forEach(function (key) {
        _defineProperty(target, key, source[key]);
      }) : Object.getOwnPropertyDescriptors ? Object.defineProperties(target, Object.getOwnPropertyDescriptors(source)) : ownKeys(Object(source)).forEach(function (key) {
        Object.defineProperty(target, key, Object.getOwnPropertyDescriptor(source, key));
      });
    }

    return target;
  }

  function _defineProperty(obj, key, value) {
    if (key in obj) {
      Object.defineProperty(obj, key, {
        value: value,
        enumerable: true,
        configurable: true,
        writable: true
      });
    } else {
      obj[key] = value;
    }

    return obj;
  }

  var commonBasicLogger = src.commonBasicLogger;

  function basicLogger$1(options) {
    return commonBasicLogger(_objectSpread2({
      destination: console.log
    }, options));
  }

  var basicLogger_1 = {
    basicLogger: basicLogger$1
  };
  var basicLogger_2 = basicLogger_1.basicLogger;

  function isSyncXhrSupported() {
    // This is temporary logic to disable synchronous XHR in Chrome 73 and above. In all other browsers,
    // we will assume it is supported. See https://github.com/launchdarkly/js-client-sdk/issues/147
    var userAgent = window.navigator && window.navigator.userAgent;

    if (userAgent) {
      var chromeMatch = userAgent.match(/Chrom(e|ium)\/([0-9]+)\./);

      if (chromeMatch) {
        var version = parseInt(chromeMatch[2], 10);
        return version < 73;
      }
    }

    return true;
  }

  var emptyResult = {
    promise: Promise.resolve({
      status: 200,
      header: function header() {
        return null;
      },
      body: null
    })
  };
  function newHttpRequest(method, url, headers, body, pageIsClosing) {
    if (pageIsClosing) {
      // When the page is about to close, we have to use synchronous XHR (until we migrate to sendBeacon).
      // But not all browsers support this.
      if (!isSyncXhrSupported()) {
        return emptyResult; // Note that we return a fake success response, because we don't want the request to be retried in this case.
      }
    }

    var xhr = new window.XMLHttpRequest();
    xhr.open(method, url, !pageIsClosing);

    for (var key in headers || {}) {
      if (Object.prototype.hasOwnProperty.call(headers, key)) {
        xhr.setRequestHeader(key, headers[key]);
      }
    }

    if (pageIsClosing) {
      xhr.send(body); // We specified synchronous mode when we called xhr.open

      return emptyResult; // Again, we never want a request to be retried in this case, so we must say it succeeded.
    } else {
      var cancelled;
      var p = new Promise(function (resolve, reject) {
        xhr.addEventListener('load', function () {
          if (cancelled) {
            return;
          }

          resolve({
            status: xhr.status,
            header: function header(key) {
              return xhr.getResponseHeader(key);
            },
            body: xhr.responseText
          });
        });
        xhr.addEventListener('error', function () {
          if (cancelled) {
            return;
          }

          reject(new Error());
        });
        xhr.send(body);
      });

      var cancel = function cancel() {
        cancelled = true;
        xhr.abort();
      };

      return {
        promise: p,
        cancel: cancel
      };
    }
  }

  function makeBrowserPlatform(options) {
    var ret = {};
    ret.synchronousFlush = false; // this will be set to true by index.js if the page is closing
    // XMLHttpRequest may not exist if we're running in a server-side rendering context

    if (window.XMLHttpRequest) {
      var disableSyncFlush = options && options.disableSyncEventPost;

      ret.httpRequest = function (method, url, headers, body) {
        var syncFlush = ret.synchronousFlush & !disableSyncFlush;
        ret.synchronousFlush = false;
        return newHttpRequest(method, url, headers, body, syncFlush);
      };
    }

    var hasCors;

    ret.httpAllowsPost = function () {
      // We compute this lazily because calling XMLHttpRequest() at initialization time can disrupt tests
      if (hasCors === undefined) {
        hasCors = window.XMLHttpRequest ? 'withCredentials' in new window.XMLHttpRequest() : false;
      }

      return hasCors;
    }; // Image-based mechanism for sending events if POST isn't available


    ret.httpFallbackPing = function (url) {
      var img = new window.Image();
      img.src = url;
    };

    var eventUrlTransformer = options && options.eventUrlTransformer;

    ret.getCurrentUrl = function () {
      return eventUrlTransformer ? eventUrlTransformer(window.location.href) : window.location.href;
    };

    ret.isDoNotTrack = function () {
      var flag;

      if (window.navigator && window.navigator.doNotTrack !== undefined) {
        flag = window.navigator.doNotTrack; // FF, Chrome
      } else if (window.navigator && window.navigator.msDoNotTrack !== undefined) {
        flag = window.navigator.msDoNotTrack; // IE 9/10
      } else {
        flag = window.doNotTrack; // IE 11+, Safari
      }

      return flag === 1 || flag === true || flag === '1' || flag === 'yes';
    };

    try {
      if (window.localStorage) {
        ret.localStorage = {
          get: function get(key) {
            return new Promise(function (resolve) {
              resolve(window.localStorage.getItem(key));
            });
          },
          set: function set(key, value) {
            return new Promise(function (resolve) {
              window.localStorage.setItem(key, value);
              resolve();
            });
          },
          clear: function clear(key) {
            return new Promise(function (resolve) {
              window.localStorage.removeItem(key);
              resolve();
            });
          }
        };
      }
    } catch (e) {
      // In some browsers (such as Chrome), even looking at window.localStorage at all will cause a
      // security error if the feature is disabled.
      ret.localStorage = null;
    } // The browser built-in EventSource implementations do not support setting the method used for
    // the request. When useReport is true, we ensure sending the user in the body of a REPORT request
    // rather than in the URL path. If a polyfill for EventSource that supports setting the request
    // method is provided (currently, launchdarkly-eventsource is the only polyfill that both supports
    // it and gives us a way to *know* that it supports it), we use the polyfill to connect to a flag
    // stream that will provide evaluated flags for the specific user. Otherwise, when useReport is
    // true, we fall back to a generic  'ping' stream that informs the SDK to make a separate REPORT
    // request for the user's flag evaluations whenever the flag definitions have been updated.


    var eventSourceConstructor;
    var useReport = options && options.useReport;

    if (useReport && typeof window.EventSourcePolyfill === 'function' && window.EventSourcePolyfill.supportedOptions && window.EventSourcePolyfill.supportedOptions.method) {
      ret.eventSourceAllowsReport = true;
      eventSourceConstructor = window.EventSourcePolyfill;
    } else {
      ret.eventSourceAllowsReport = false;
      eventSourceConstructor = window.EventSource;
    } // If EventSource does not exist, the absence of eventSourceFactory will make us not try to open streams


    if (window.EventSource) {
      var timeoutMillis = 300000; // this is only used by polyfills - see below

      ret.eventSourceFactory = function (url, options) {
        // The standard EventSource constructor doesn't take any options, just a URL. However, some
        // EventSource polyfills allow us to specify a timeout interval, and in some cases they will
        // default to a too-short timeout if we don't specify one. So, here, we are setting the
        // timeout properties that are used by several popular polyfills.
        // Also, the skipDefaultHeaders property (if supported) tells the polyfill not to add the
        // Cache-Control header that can cause CORS problems in browsers.
        // See: https://github.com/launchdarkly/js-eventsource
        var defaultOptions = {
          heartbeatTimeout: timeoutMillis,
          silentTimeout: timeoutMillis,
          skipDefaultHeaders: true
        };

        var esOptions = _objectSpread2(_objectSpread2({}, defaultOptions), options);

        return new eventSourceConstructor(url, esOptions);
      };

      ret.eventSourceIsActive = function (es) {
        return es.readyState === window.EventSource.OPEN || es.readyState === window.EventSource.CONNECTING;
      };
    }

    ret.userAgent = 'JSClient';
    ret.version = "2.22.1";
    ret.diagnosticSdkData = {
      name: 'js-client-sdk',
      version: "2.22.1"
    };
    ret.diagnosticPlatformData = {
      name: 'JS'
    };
    ret.diagnosticUseCombinedEvent = true; // the browser SDK uses the "diagnostic-combined" event format

    return ret;
  }

  var matchOperatorsRe = /[|\\{}()[\]^$+*?.]/g;

  var escapeStringRegexp = function (str) {
  	if (typeof str !== 'string') {
  		throw new TypeError('Expected a string');
  	}

  	return str.replace(matchOperatorsRe, '\\$&');
  };

  function doesUrlMatch(matcher, href, search, hash) {
    var keepHash = (matcher.kind === 'substring' || matcher.kind === 'regex') && hash.includes('/');
    var canonicalUrl = (keepHash ? href : href.replace(hash, '')).replace(search, '');
    var regex;
    var testUrl;

    switch (matcher.kind) {
      case 'exact':
        testUrl = href;
        regex = new RegExp('^' + escapeStringRegexp(matcher.url) + '/?$');
        break;

      case 'canonical':
        testUrl = canonicalUrl;
        regex = new RegExp('^' + escapeStringRegexp(matcher.url) + '/?$');
        break;

      case 'substring':
        testUrl = canonicalUrl;
        regex = new RegExp('.*' + escapeStringRegexp(matcher.substring) + '.*$');
        break;

      case 'regex':
        testUrl = canonicalUrl;
        regex = new RegExp(matcher.pattern);
        break;

      default:
        return false;
    }

    return regex.test(testUrl);
  }

  function findGoalsForClick(event, clickGoals) {
    var matches = [];

    for (var i = 0; i < clickGoals.length; i++) {
      var target = event.target;
      var goal = clickGoals[i];
      var selector = goal.selector;
      var elements = document.querySelectorAll(selector);

      while (target && elements.length > 0) {
        for (var j = 0; j < elements.length; j++) {
          if (target === elements[j]) {
            matches.push(goal);
          }
        }

        target = target.parentNode;
      }
    }

    return matches;
  }

  function GoalTracker(goals, onEvent) {
    var tracker = {};
    var listenerFn = null;
    var clickGoals = [];

    for (var i = 0; i < goals.length; i++) {
      var goal = goals[i];
      var urls = goal.urls || [];

      for (var j = 0; j < urls.length; j++) {
        if (doesUrlMatch(urls[j], window.location.href, window.location.search, window.location.hash)) {
          if (goal.kind === 'pageview') {
            onEvent('pageview', goal);
          } else {
            clickGoals.push(goal);
            onEvent('click_pageview', goal);
          }

          break;
        }
      }
    }

    if (clickGoals.length > 0) {
      listenerFn = function listenerFn(event) {
        var goals = findGoalsForClick(event, clickGoals);

        for (var _i = 0; _i < goals.length; _i++) {
          onEvent('click', goals[_i]);
        }
      };

      document.addEventListener('click', listenerFn);
    }

    tracker.dispose = function () {
      document.removeEventListener('click', listenerFn);
    };

    return tracker;
  }

  var locationWatcherInterval = 300;
  function GoalManager(clientVars, readyCallback) {
    var goals;
    var goalTracker;
    var ret = {};

    function getGoalsPath() {
      return '/sdk/goals/' + clientVars.getEnvironmentId();
    }

    function refreshGoalTracker() {
      if (goalTracker) {
        goalTracker.dispose();
      }

      if (goals && goals.length) {
        goalTracker = GoalTracker(goals, sendGoalEvent);
      }
    }

    function sendGoalEvent(kind, goal) {
      var user = clientVars.ident.getUser();
      var event = {
        kind: kind,
        key: goal.key,
        data: null,
        url: window.location.href,
        user: user,
        creationDate: new Date().getTime()
      };

      if (user && user.anonymous) {
        event.contextKind = 'anonymousUser';
      }

      if (kind === 'click') {
        event.selector = goal.selector;
      }

      return clientVars.enqueueEvent(event);
    }

    function watchLocation(interval, callback) {
      var previousUrl = window.location.href;
      var currentUrl;

      function checkUrl() {
        currentUrl = window.location.href;

        if (currentUrl !== previousUrl) {
          previousUrl = currentUrl;
          callback();
        }
      }

      function poll(fn, interval) {
        fn();
        setTimeout(function () {
          poll(fn, interval);
        }, interval);
      }

      poll(checkUrl, interval);

      if (window.history && window.history.pushState) {
        window.addEventListener('popstate', checkUrl);
      } else {
        window.addEventListener('hashchange', checkUrl);
      }
    }

    clientVars.requestor.fetchJSON(getGoalsPath()).then(function (g) {
      if (g && g.length > 0) {
        goals = g;
        goalTracker = GoalTracker(goals, sendGoalEvent);
        watchLocation(locationWatcherInterval, refreshGoalTracker);
      }

      readyCallback();
    }).catch(function (err) {
      clientVars.emitter.maybeReportError(new src_3.LDUnexpectedResponseError('Error fetching goals: ' + (err && err.message) ? err.message : err));
      readyCallback();
    });
    return ret;
  }

  var goalsEvent = 'goalsReady';
  var extraOptionDefs = {
    fetchGoals: {
      default: true
    },
    hash: {
      type: 'string'
    },
    eventProcessor: {
      type: 'object'
    },
    // used only in tests
    eventUrlTransformer: {
      type: 'function'
    },
    disableSyncEventPost: {
      default: false
    }
  }; // Pass our platform object to the common code to create the browser version of the client

  function initialize(env, user) {
    var options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
    var platform = makeBrowserPlatform(options);
    var clientVars = src_1(env, user, options, platform, extraOptionDefs);
    var client = clientVars.client;
    var validatedOptions = clientVars.options;
    var emitter = clientVars.emitter;
    var goalsPromise = new Promise(function (resolve) {
      var onGoals = emitter.on(goalsEvent, function () {
        emitter.off(goalsEvent, onGoals);
        resolve();
      });
    });

    client.waitUntilGoalsReady = function () {
      return goalsPromise;
    };

    if (validatedOptions.fetchGoals) {
      GoalManager(clientVars, function () {
        return emitter.emit(goalsEvent);
      }); // Don't need to save a reference to the GoalManager - its constructor takes care of setting
      // up the necessary event wiring
    } else {
      emitter.emit(goalsEvent);
    }

    if (document.readyState !== 'complete') {
      window.addEventListener('load', clientVars.start);
    } else {
      clientVars.start();
    } // We'll attempt to flush events via synchronous HTTP if the page is about to close, to improve
    // the chance that the events will really be delivered, although synchronous requests aren't
    // supported in all browsers (see httpRequest.js). We will do it for both beforeunload and
    // unload, in case any events got generated by code that ran in another beforeunload handler.
    // We will not call client.close() though, since in the case of a beforeunload event the page
    // might not actually get closed, and with an unload event we know everything will get discarded
    // anyway.


    var syncFlushHandler = function syncFlushHandler() {
      platform.synchronousFlush = true;
      client.flush().catch(function () {});
      platform.synchronousFlush = false;
    };

    window.addEventListener('beforeunload', syncFlushHandler);
    window.addEventListener('unload', syncFlushHandler);
    return client;
  }
  var basicLogger = basicLogger_2;
  var createConsoleLogger = undefined;
  var version = "2.22.1";

  function deprecatedInitialize(env, user) {
    var options = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : {};
    console && console.warn && console.warn(src_4.deprecated('default export', 'named LDClient export')); // eslint-disable-line no-console

    return initialize(env, user, options);
  }

  var index = {
    initialize: deprecatedInitialize,
    version: version
  };

  exports.basicLogger = basicLogger;
  exports.createConsoleLogger = createConsoleLogger;
  exports["default"] = index;
  exports.initialize = initialize;
  exports.version = version;

  Object.defineProperty(exports, '__esModule', { value: true });

}));
//# sourceMappingURL=ldclient.js.map

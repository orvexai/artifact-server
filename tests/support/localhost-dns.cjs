const dns = require("node:dns");

const systemLookup = dns.lookup;

dns.lookup = function testLookup(hostname, options, callback) {
  if (arguments.length === 2) {
    callback = options;
    options = {};
  }
  if (!hostname.endsWith(".localhost")) {
    systemLookup(hostname, options, callback);
    return;
  }
  const lookupOptions = Object(options);
  const all = Object.hasOwn(lookupOptions, "all") && lookupOptions.all === true;
  queueMicrotask(() => all
    ? callback(null, [{address: "127.0.0.1", family: 4}])
    : callback(null, "127.0.0.1", 4));
  return;
};

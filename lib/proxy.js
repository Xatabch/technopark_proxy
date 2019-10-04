'use strict';

var async = require('async');
var net = require('net');
var http = require('http');
var https = require('https');
var util = require('util');
var fs = require('fs');
var events = require('events');
var url = require('url');
var semaphore = require('semaphore');
const nodeCommon = require('_http_common');
const debug = require('debug')('http-mitm-proxy');

module.exports = function() {
  return new Proxy();
};

var Proxy = function() {
  this.onConnectHandlers = [];
  this.onRequestHandlers = [];
  this.onRequestHeadersHandlers = [];
  this.onWebSocketConnectionHandlers = [];
  this.onWebSocketFrameHandlers = [];
  this.onWebSocketCloseHandlers = [];
  this.onWebSocketErrorHandlers = [];
  this.onErrorHandlers = [];
  this.onRequestDataHandlers = [];
  this.onRequestEndHandlers = [];
  this.onResponseHandlers = [];
  this.onResponseHeadersHandlers = [];
  this.onResponseDataHandlers = [];
  this.onResponseEndHandlers = [];
  this.responseContentPotentiallyModified = false;
};

module.exports.Proxy = Proxy;

Proxy.prototype.listen = function(options = {}) {
  this.options = options;
  this.httpPort = options.port || options.port === 0 ? options.port : 8080;
  this.httpHost = options.host;
  this.timeout = options.timeout || 0;
  this.keepAlive = !!options.keepAlive;
  this.httpAgent = typeof(options.httpAgent) !== "undefined" ? options.httpAgent : new http.Agent({ keepAlive: this.keepAlive });
  this.connectRequests = {};

  this.httpServer = http.createServer();
  this.httpServer.timeout = this.timeout;
  this.httpServer.on('connect', this._onHttpServerConnect.bind(this));
  this.httpServer.on('request', this._onHttpServerRequest.bind(this, false));

  const listenOptions = {
    host: this.httpHost,
    port: this.httpPort
  };

  this.httpServer.listen(listenOptions);
};

Proxy.prototype.onError = function(fn) {
  this.onErrorHandlers.push(fn);
  return this;
};

Proxy.prototype.onConnect = function(fn) {
  this.onConnectHandlers.push(fn);
  return this;
};

Proxy.prototype.onRequestHeaders = function(fn) {
  this.onRequestHeadersHandlers.push(fn);
  return this;
};

Proxy.prototype.onRequest = function(fn) {
  this.onRequestHandlers.push(fn);
  return this;
};

Proxy.prototype.onRequestData = function(fn) {
  this.onRequestDataHandlers.push(fn);
  return this;
};

Proxy.prototype.onRequestEnd = function(fn) {
  this.onRequestEndHandlers.push(fn);
  return this;
};

Proxy.prototype.onResponse = function(fn) {
  this.onResponseHandlers.push(fn);
  return this;
};

Proxy.prototype.onResponseHeaders = function(fn) {
  this.onResponseHeadersHandlers.push(fn);
  return this;
};

Proxy.prototype.onResponseData = function(fn) {
  this.onResponseDataHandlers.push(fn);
  this.responseContentPotentiallyModified = true;
  return this;
};

Proxy.prototype.onResponseEnd = function(fn) {
  this.onResponseEndHandlers.push(fn);
  return this;
};

Proxy.prototype.use = function(mod) {
  if (mod.onError) {
    this.onError(mod.onError);
  }
  if (mod.onCertificateRequired) {
    this.onCertificateRequired = mod.onCertificateRequired;
  }
  if (mod.onCertificateMissing) {
    this.onCertificateMissing = mod.onCertificateMissing;
  }
  if (mod.onConnect) {
    this.onConnect(mod.onConnect);
  }
  if (mod.onRequest) {
    this.onRequest(mod.onRequest);
  }
  if (mod.onRequestHeaders) {
    this.onRequestHeaders(mod.onRequestHeaders);
  }
  if (mod.onRequestData) {
    this.onRequestData(mod.onRequestData);
  }
  if (mod.onResponse) {
    this.onResponse(mod.onResponse);
  }
  if (mod.onResponseHeaders) {
    this.onResponseHeaders(mod.onResponseHeaders);
  }
  if (mod.onResponseData) {
    this.onResponseData(mod.onResponseData);
  }
  if (mod.onWebSocketConnection) {
    this.onWebSocketConnection(mod.onWebSocketConnection);
  }
  if (mod.onWebSocketSend) {
    this.onWebSocketFrame(function(ctx, type, fromServer, data, flags, callback) {
      if (!fromServer && type === 'message') return this(ctx, data, flags, callback);
      else callback(null, data, flags);
    }.bind(mod.onWebSocketSend));
  }
  if (mod.onWebSocketMessage) {
    this.onWebSocketFrame(function(ctx, type, fromServer, data, flags, callback) {
      if (fromServer && type === 'message') return this(ctx, data, flags, callback);
      else callback(null, data, flags);
    }.bind(mod.onWebSocketMessage));
  }
  if (mod.onWebSocketFrame) {
    this.onWebSocketFrame(mod.onWebSocketFrame);
  }
  if (mod.onWebSocketClose) {
    this.onWebSocketClose(mod.onWebSocketClose);
  }
  if (mod.onWebSocketError) {
    this.onWebSocketError(mod.onWebSocketError);
  }
  return this;
};

Proxy.prototype._onSocketError = function(socketDescription, err) {
  if (err.errno === 'ECONNRESET') {
    debug('Got ECONNRESET on ' + socketDescription + ', ignoring.');
  } else {
    this._onError(socketDescription + '_ERROR', null, err);
  }
};

Proxy.prototype._onHttpServerConnect = function(req, socket, head) {
  var self = this;

  socket.on('error', self._onSocketError.bind(self, 'CLIENT_TO_PROXY_SOCKET'));

  // you can forward HTTPS request directly by adding custom CONNECT method handler
  return async.forEach(self.onConnectHandlers, function (fn, callback) {
    return fn.call(self, req, socket, head, callback)
  }, function (err) {
    if (err) {
      return self._onError('ON_CONNECT_ERROR', null, err);
    }
    // we need first byte of data to detect if request is SSL encrypted
    if (!head || head.length === 0) {
        socket.once('data', self._onHttpServerConnectData.bind(self, req, socket));
        socket.write('HTTP/1.1 200 OK\r\n');
        if (self.keepAlive && req.headers['proxy-connection'] === 'keep-alive') {
          socket.write('Proxy-Connection: keep-alive\r\n');
          socket.write('Connection: keep-alive\r\n');
        }
        return socket.write('\r\n');
    } else {
      self._onHttpServerConnectData(req, socket, head)
    }
  })
};

Proxy.prototype._onHttpServerConnectData = function(req, socket, head) {
  var self = this;

  socket.pause();

  if (head[0] == 0x16 || head[0] == 0x80 || head[0] == 0x00) {

    var hostname = req.url.split(':', 2)[0];
    var sslServer = this.sslServers[hostname];
    if (sslServer) {
      return makeConnection(sslServer.port);
    }
    var wildcardHost = hostname.replace(/[^\.]+\./, '*.');
    var sem = self.sslSemaphores[wildcardHost];
    if (!sem) {
      sem = self.sslSemaphores[wildcardHost] = semaphore(1);
    }
    sem.take(function() {
      if (self.sslServers[hostname]) {
        process.nextTick(sem.leave.bind(sem));
        return makeConnection(self.sslServers[hostname].port);
      }
      if (self.sslServers[wildcardHost]) {
        process.nextTick(sem.leave.bind(sem));
        self.sslServers[hostname] = {
          port: self.sslServers[wildcardHost]
        };
        return makeConnection(self.sslServers[hostname].port);
      }
      getHttpsServer(hostname, function(err, port) {
        process.nextTick(sem.leave.bind(sem));
        if (err) {
          return self._onError('OPEN_HTTPS_SERVER_ERROR', null, err);
        }
        return makeConnection(port);
      });
    });
  } else {
    return makeConnection(this.httpPort);
  }

  function makeConnection(port) {
    // open a TCP connection to the remote host
    var conn = net.connect({
      port: port,
      allowHalfOpen: true
    }, function() {
      // create a tunnel between the two hosts
      conn.on('finish', () => {
        socket.destroy();
      });
      socket.on('close', () => {
        conn.end();
      });
      var connectKey = conn.localPort + ':' + conn.remotePort;
      self.connectRequests[connectKey] = req; 
      socket.pipe(conn);
      conn.pipe(socket);
      socket.emit('data', head);
      conn.on('end', function() { delete self.connectRequests[connectKey]; });
      return socket.resume();
    });
    conn.on('error', self._onSocketError.bind(self, 'PROXY_TO_PROXY_SOCKET'));
  }

  function getHttpsServer(hostname, callback) {
    self.onCertificateRequired(hostname, function (err, files) {
      if (err) {
        return callback(err);
      }
      async.auto({
        'keyFileExists': function(callback) {
          return fs.exists(files.keyFile, function(exists) {
            return callback(null, exists);
          });
        },
        'certFileExists': function(callback) {
          return fs.exists(files.certFile, function(exists) {
            return callback(null, exists);
          });
        },
        'httpsOptions': ['keyFileExists', 'certFileExists', function(data, callback) {
          if (data.keyFileExists && data.certFileExists) {
            return fs.readFile(files.keyFile, function(err, keyFileData) {
              if (err) {
                return callback(err);
              }

              return fs.readFile(files.certFile, function(err, certFileData) {
                if (err) {
                  return callback(err);
                }

                return callback(null, {
                  key: keyFileData,
                  cert: certFileData,
                  hosts: files.hosts
                });
              });
            });
          } else {
            var ctx = {
              'hostname': hostname,
              'files': files,
              'data': data
            };

            return self.onCertificateMissing(ctx, files, function(err, files) {
              if (err) {
                return callback(err);
              }

              return callback(null, {
                key: files.keyFileData,
                cert: files.certFileData,
                hosts: files.hosts
              });
            });
          }
        }]
      }, function(err, results) {
        if (err) {
          return callback(err);
        }
        var hosts;
        if (results.httpsOptions && results.httpsOptions.hosts && results.httpsOptions.hosts.length) {
          hosts = results.httpsOptions.hosts;
          if (hosts.indexOf(hostname) === -1) {
            hosts.push(hostname);
          }
        } else {
          hosts = [hostname];
        }
        delete results.httpsOptions.hosts;
        if (self.forceSNI && !hostname.match(/^[\d\.]+$/)) {
          debug('creating SNI context for ' + hostname);
          hosts.forEach(function(host) {
            self.httpsServer.addContext(host, results.httpsOptions);
            self.sslServers[host] = { port : self.httpsPort };
          });
          return callback(null, self.httpsPort);
        } else {
          debug('starting server for ' + hostname);
          results.httpsOptions.hosts = hosts;
          self._createHttpsServer(results.httpsOptions, function(port, httpsServer, wssServer) {
            debug('https server started for %s on %s', hostname, port);
            var sslServer = {
              server: httpsServer,
              wsServer: wssServer,
              port: port
            };
            hosts.forEach(function(host) {
              self.sslServers[hostname] = sslServer;
            });
            return callback(null, port);
          });
        }
      });
    });
  }
};

Proxy.prototype._onError = function(kind, ctx, err) {
  this.onErrorHandlers.forEach(function(handler) {
    return handler(ctx, err, kind);
  });
  if (ctx) {
    ctx.onErrorHandlers.forEach(function(handler) {
      return handler(ctx, err, kind);
    });

    if (ctx.proxyToClientResponse && !ctx.proxyToClientResponse.headersSent) {
      ctx.proxyToClientResponse.writeHead(504, 'Proxy Error');
    }
    if (ctx.proxyToClientResponse && !ctx.proxyToClientResponse.finished) {
      ctx.proxyToClientResponse.end(''+kind+': '+err, 'utf8');
    }
  }
};

Proxy.prototype._onHttpServerRequest = function(isSSL, clientToProxyRequest, proxyToClientResponse) {
  var self = this;
  var ctx = {
    isSSL: isSSL,
    connectRequest: self.connectRequests[clientToProxyRequest.socket.remotePort + ':' + clientToProxyRequest.socket.localPort] || {},
    clientToProxyRequest: clientToProxyRequest,
    proxyToClientResponse: proxyToClientResponse,
    onRequestHandlers: [],
    onErrorHandlers: [],
    onRequestDataHandlers: [],
    onRequestEndHandlers: [],
    onResponseHandlers: [],
    onResponseDataHandlers: [],
    onResponseEndHandlers: [],
    requestFilters: [],
    responseFilters: [],
    responseContentPotentiallyModified: false,
    onRequest: function(fn) {
      ctx.onRequestHandlers.push(fn);
      return ctx;
    },
    onError: function(fn) {
      ctx.onErrorHandlers.push(fn);
      return ctx;
    },
    onRequestData: function(fn) {
      ctx.onRequestDataHandlers.push(fn);
      return ctx;
    },
    onRequestEnd: function(fn) {
      ctx.onRequestEndHandlers.push(fn);
      return ctx;
    },
    onResponse: function(fn) {
      ctx.onResponseHandlers.push(fn);
      return ctx;
    },
    onResponseData: function(fn) {
      ctx.onResponseDataHandlers.push(fn);
      ctx.responseContentPotentiallyModified = true;
      return ctx;
    },
    onResponseEnd: function(fn) {
      ctx.onResponseEndHandlers.push(fn);
      return ctx;
    }
  };

  ctx.clientToProxyRequest.on('error', self._onError.bind(self, 'CLIENT_TO_PROXY_REQUEST_ERROR', ctx));
  ctx.proxyToClientResponse.on('error', self._onError.bind(self, 'PROXY_TO_CLIENT_RESPONSE_ERROR', ctx));
  ctx.clientToProxyRequest.pause();
  var hostPort = Proxy.parseHostAndPort(ctx.clientToProxyRequest, ctx.isSSL ? 443 : 80);
  var headers = {};
  for (var h in ctx.clientToProxyRequest.headers) {
    // don't forward proxy- headers
    if (!/^proxy\-/i.test(h)) {
      headers[h] = ctx.clientToProxyRequest.headers[h];
    }
  }
  if (this.options.forceChunkedRequest){
    delete headers['content-length'];
  }

  ctx.proxyToServerRequestOptions = {
    method: ctx.clientToProxyRequest.method,
    path: ctx.clientToProxyRequest.url,
    host: hostPort.host,
    port: hostPort.port,
    headers: headers,
    agent: ctx.isSSL ? self.httpsAgent : self.httpAgent
  };

  return self._onRequest(ctx, function(err) {
    if (err) {
      return self._onError('ON_REQUEST_ERROR', ctx, err);
    }
    return self._onRequestHeaders(ctx, function(err) {
      if (err) {
        return self._onError('ON_REQUESTHEADERS_ERROR', ctx, err);
      }
      return makeProxyToServerRequest();
    });
  });

  function makeProxyToServerRequest() {
    var proto = ctx.isSSL ? https : http;
    ctx.proxyToServerRequest = proto.request(ctx.proxyToServerRequestOptions, proxyToServerRequestComplete);
    ctx.proxyToServerRequest.on('error', self._onError.bind(self, 'PROXY_TO_SERVER_REQUEST_ERROR', ctx));
    ctx.requestFilters.push(new ProxyFinalRequestFilter(self, ctx));
    var prevRequestPipeElem = ctx.clientToProxyRequest;
    ctx.requestFilters.forEach(function(filter) {
      filter.on('error', self._onError.bind(self, 'REQUEST_FILTER_ERROR', ctx));
      prevRequestPipeElem = prevRequestPipeElem.pipe(filter);
    });
    ctx.clientToProxyRequest.resume();
  }

  function proxyToServerRequestComplete(serverToProxyResponse) {
    serverToProxyResponse.on('error', self._onError.bind(self, 'SERVER_TO_PROXY_RESPONSE_ERROR', ctx));
    serverToProxyResponse.pause();
    ctx.serverToProxyResponse = serverToProxyResponse;

    return self._onResponse(ctx, function(err) {
      if (err) {
        return self._onError('ON_RESPONSE_ERROR', ctx, err);
      }

      if (self.responseContentPotentiallyModified || ctx.responseContentPotentiallyModified) {
        ctx.serverToProxyResponse.headers['transfer-encoding'] = 'chunked';
        delete ctx.serverToProxyResponse.headers['content-length'];  
      }

      if (self.keepAlive) {
        if (ctx.clientToProxyRequest.headers['proxy-connection']) {
          ctx.serverToProxyResponse.headers['proxy-connection'] = 'keep-alive';
          ctx.serverToProxyResponse.headers['connection'] = 'keep-alive';
        }
      } else {
        ctx.serverToProxyResponse.headers['connection'] = 'close';
      }

      return self._onResponseHeaders(ctx, function (err) {
        if (err) {
          return self._onError('ON_RESPONSEHEADERS_ERROR', ctx, err);
        }
        ctx.proxyToClientResponse.writeHead(ctx.serverToProxyResponse.statusCode, Proxy.filterAndCanonizeHeaders(ctx.serverToProxyResponse.headers));
        ctx.responseFilters.push(new ProxyFinalResponseFilter(self, ctx));
        var prevResponsePipeElem = ctx.serverToProxyResponse;
        ctx.responseFilters.forEach(function(filter) {
          filter.on('error', self._onError.bind(self, 'RESPONSE_FILTER_ERROR', ctx));
          prevResponsePipeElem = prevResponsePipeElem.pipe(filter);
        });
        return ctx.serverToProxyResponse.resume();
      });
    });
  }
};

var ProxyFinalRequestFilter = function(proxy, ctx) {
  events.EventEmitter.call(this);
  this.writable = true;

  this.write = function(chunk) {
    proxy._onRequestData(ctx, chunk, function(err, chunk) {
      if (err) {
        return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err);
      }
      if (chunk) {
        return ctx.proxyToServerRequest.write(chunk);
      }
    });
    return true;
  };

  this.end = function(chunk) {
    if (chunk) {
      return proxy._onRequestData(ctx, chunk, function(err, chunk) {
        if (err) {
          return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err);
        }

        return proxy._onRequestEnd(ctx, function (err) {
          if (err) {
            return proxy._onError('ON_REQUEST_END_ERROR', ctx, err);
          }
          return ctx.proxyToServerRequest.end(chunk);
        });
      });
    } else {
      return proxy._onRequestEnd(ctx, function (err) {
        if (err) {
          return proxy._onError('ON_REQUEST_END_ERROR', ctx, err);
        }
        return ctx.proxyToServerRequest.end(chunk || undefined);
      });
    }
  };
};
util.inherits(ProxyFinalRequestFilter, events.EventEmitter);

var ProxyFinalResponseFilter = function(proxy, ctx) {
  events.EventEmitter.call(this);
  this.writable = true;

  this.write = function(chunk) {
    proxy._onResponseData(ctx, chunk, function(err, chunk) {
      if (err) {
        return proxy._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
      }
      if (chunk) {
        return ctx.proxyToClientResponse.write(chunk);
      }
    });
    return true;
  };

  this.end = function(chunk) {
    if (chunk) {
      return proxy._onResponseData(ctx, chunk, function(err, chunk) {
        if (err) {
          return proxy._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
        }

        return proxy._onResponseEnd(ctx, function (err) {
          if (err) {
            return proxy._onError('ON_RESPONSE_END_ERROR', ctx, err);
          }
          return ctx.proxyToClientResponse.end(chunk || undefined);
        });
      });
    } else {
      return proxy._onResponseEnd(ctx, function (err) {
        if (err) {
          return proxy._onError('ON_RESPONSE_END_ERROR', ctx, err);
        }
        return ctx.proxyToClientResponse.end(chunk || undefined);
      });
    }
  };

  return this;
};
util.inherits(ProxyFinalResponseFilter, events.EventEmitter);

Proxy.prototype._onRequestHeaders = function(ctx, callback) {
  async.forEach(this.onRequestHeadersHandlers, function(fn, callback) {
    return fn(ctx, callback);
  }, callback);
};

Proxy.prototype._onRequest = function(ctx, callback) {
  async.forEach(this.onRequestHandlers.concat(ctx.onRequestHandlers), function(fn, callback) {
    return fn(ctx, callback);
  }, callback);
};

Proxy.prototype._onRequestData = function(ctx, chunk, callback) {
  var self = this;
  async.forEach(this.onRequestDataHandlers.concat(ctx.onRequestDataHandlers), function(fn, callback) {
    return fn(ctx, chunk, function(err, newChunk) {
      if (err) {
        return callback(err);
      }
      chunk = newChunk;
      return callback(null, newChunk);
    });
  }, function(err) {
    if (err) {
      return self._onError('ON_REQUEST_DATA_ERROR', ctx, err);
    }
    return callback(null, chunk);
  });
};

Proxy.prototype._onRequestEnd = function(ctx, callback) {
  var self = this;
  async.forEach(this.onRequestEndHandlers.concat(ctx.onRequestEndHandlers), function(fn, callback) {
    return fn(ctx, callback);
  }, function(err) {
    if (err) {
      return self._onError('ON_REQUEST_END_ERROR', ctx, err);
    }
    return callback(null);
  });
};

Proxy.prototype._onResponse = function(ctx, callback) {
  async.forEach(this.onResponseHandlers.concat(ctx.onResponseHandlers), function(fn, callback) {
    return fn(ctx, callback);
  }, callback);
};

Proxy.prototype._onResponseHeaders = function(ctx, callback) {
  async.forEach(this.onResponseHeadersHandlers, function(fn, callback) {
    return fn(ctx, callback);
  }, callback);
};

Proxy.prototype._onResponseData = function(ctx, chunk, callback) {
  var self = this;
  async.forEach(this.onResponseDataHandlers.concat(ctx.onResponseDataHandlers), function(fn, callback) {
    return fn(ctx, chunk, function(err, newChunk) {
      if (err) {
        return callback(err);
      }
      chunk = newChunk;
      return callback(null, newChunk);
    });
  }, function(err) {
    if (err) {
      return self._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
    }
    return callback(null, chunk);
  });
};

Proxy.prototype._onResponseEnd = function(ctx, callback) {
  var self = this;
  async.forEach(this.onResponseEndHandlers.concat(ctx.onResponseEndHandlers), function(fn, callback) {
    return fn(ctx, callback);
  }, function(err) {
    if (err) {
      return self._onError('ON_RESPONSE_END_ERROR', ctx, err);
    }
    return callback(null);
  });
};

Proxy.parseHostAndPort = function(req, defaultPort) {
  var host = req.headers.host;
  if (!host) {
    return null;
  }
  var hostPort = Proxy.parseHost(host, defaultPort);

  // this handles paths which include the full url. This could happen if it's a proxy
  var m = req.url.match(/^http:\/\/([^\/]*)\/?(.*)$/);
  if (m) {
    var parsedUrl = url.parse(req.url);
    hostPort.host = parsedUrl.hostname;
    hostPort.port = parsedUrl.port;
    req.url = parsedUrl.path;
  }

  return hostPort;
};

Proxy.parseHost = function(hostString, defaultPort) {
  var m = hostString.match(/^http:\/\/(.*)/);
  if (m) {
    var parsedUrl = url.parse(hostString);
    return {
      host: parsedUrl.hostname,
      port: parsedUrl.port
    };
  }

  var hostPort = hostString.split(':');
  var host = hostPort[0];
  var port = hostPort.length === 2 ? +hostPort[1] : defaultPort;

  return {
    host: host,
    port: port
  };
};

Proxy.filterAndCanonizeHeaders = function(originalHeaders) {
  var headers = {};
  for (var key in originalHeaders) {
    var canonizedKey = key.trim();
    if (/^public\-key\-pins/i.test(canonizedKey)) {
      // HPKP header => filter
      continue;
    }

    if (!nodeCommon._checkInvalidHeaderChar(originalHeaders[key])) {
      headers[canonizedKey] = originalHeaders[key];
    }
  }

  return headers;
};

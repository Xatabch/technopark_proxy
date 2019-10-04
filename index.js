'use strict';

var port = 8081;

var Proxy = require('./lib/proxy.js');
var proxy = Proxy();

proxy.onError(function(ctx, err, errorKind) {
  // ctx may be null
  var url = (ctx && ctx.clientToProxyRequest) ? ctx.clientToProxyRequest.url : '';
  console.error(errorKind + ' on ' + url + ':', err);
});

proxy.onRequest(function(ctx, callback) {
  return callback();
});

proxy.onResponse(function(ctx, callback) {
  const chunks = [];

  ctx.onResponseData(function(ctx, chunk, callback) {
    chunks.push(chunk);
    return callback(null, null);
  });

  ctx.onResponseEnd(function(ctx, callback) {
    let body = Buffer.concat(chunks);
    body = body.toString().replace(/TEST/g, 'LOL');
    ctx.proxyToClientResponse.write(body);
    return callback();
  })

  return callback();
})

proxy.listen({ port: port });
console.log('listening on ' + port);
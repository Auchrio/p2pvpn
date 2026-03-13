// Package bridge embeds the static web-bridge client (bridge.html) and the
// companion Service Worker (sw.js) so they can be served directly from the
// daemon binary without runtime file-system access.
package bridge

import _ "embed"

// HTML is the single-file web bridge client.
//
//go:embed bridge.html
var HTML []byte

// SWJS is the Service Worker script that intercepts requests to VPN addresses
// and routes them through the daemon's /api/bridge/proxy endpoint.
//
//go:embed sw.js
var SWJS []byte

'use strict';
var socketio = require('socket.io');
var io = null;
var mongoose = require("mongoose");
var ee = require('../app/configure/event.js').ee;

module.exports = function (server) {

    if (io) return io;

    io = socketio(server);

	ee.on("randomize", function (newInfo, oldinfo) {
		io.sockets.emit("randomize", newInfo, oldinfo);
	});

    return io;

};

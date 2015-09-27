'use strict';
var mongoose = require('mongoose');

var schema = new mongoose.Schema({
    status: {
        type: String,
        enum: ['safe', 'broken'],
        required: true,
        default: 'safe'
    },
    email: {
        type: String
    },
    date: {
        type: Date,
        default: Date.now,
        required: true
    },
    time: {
        type: String
    }
})

mongoose.model('Alert', schema);

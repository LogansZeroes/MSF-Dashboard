'use strict';
var mongoose = require('mongoose');
var validator = require('email-validator');


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
    },
    temp: String
});

schema.path('email').validate(function (value) {
    return validator.validate(value);
});

mongoose.model('Alert', schema);

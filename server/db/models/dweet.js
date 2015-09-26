'use strict';
var mongoose = require('mongoose');

var schema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    created: {
        type: Date,
        required: true,
        unique: true
    },
    temp: {
        type: String,
        required: true
    }
})

mongoose.model('Dweet', schema);

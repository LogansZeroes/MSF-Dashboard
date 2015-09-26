'use strict';
var mongoose = require('mongoose');

var schema = new mongoose.Schema({
    name: String,
    created: Date,
    temp: String
})

mongoose.model('Dweet', schema);

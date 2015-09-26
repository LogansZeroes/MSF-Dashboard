var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var sinon = require('sinon');
var expect = require('chai').expect;
var mongoose = require('mongoose');

// Require in all models.
require('../../../server/db/models');

var Dweet = mongoose.model('Dweet');

describe('Dweet Model', function () {

    beforeEach('Establish DB Connection', function (done) {
        if (mongoose.connection.db) return done();
        mongoose.connect(dbURI, done);
    });

    afterEach('Clear the test database', function (done) {
        clearDB(done);
    });

    it('Should exist', function () {
        expect(Dweet).to.be.a('function');
    });

    describe('Validation', function () {

        var date = new Date();
        var createDweet = function () {
            return Dweet.create({
                name: 'Temp Temp',
                created: date,
                temp: '55.5'
            });
        }

        it('Should have all fields else error', function (done) {
            Dweet.create({})
            .then(null, function (error) {
                expect(error.name).to.equal('ValidationError');
                expect(error.errors.name).to.exist;
                expect(error.errors.created).to.exist;
                expect(error.errors.temp).to.exist;
                done();
            })
        })

        it('Should have a unique create date else error', function (done) {
            createDweet()
            .then( function () {
                return createDweet();
            })
            .then (null, function (error) {
                expect(error).to.be.ok;
                expect(error.code).to.equal(11000);
                expect(error.name).to.equal('MongoError');
                done();
            })
        })



    })



})

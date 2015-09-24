var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var sinon = require('sinon');
var expect = require('chai').expect;
var mongoose = require('mongoose');

// Require in all models.
require('../../../server/db/models');

var User = mongoose.model('User');
var Store = mongoose.model('Store');


describe('Store model', function () {

    beforeEach('Establish DB connection', function (done) {
        if (mongoose.connection.db) return done();
        mongoose.connect(dbURI, done);
    });

    afterEach('Clear test database', function (done) {
        clearDB(done);
    });

    it('should exist', function () {
        expect(Store).to.be.a('function');
    });

    describe('Store model', function () {

        describe('Validation', function () {

            var userId;

            beforeEach('make a user', function (done) {
                User.create({email: "sean@sean.com", password: "mypass"})
                .then(function (user) {
                    userId = user._id;
                    done();
                })
                .then(null, done);
            });

            it('should err without user, url', function (done) {

                Store.create({})
                .then(function (store) {
                    //shouldn't go here
                    console.log(store);
                    done();
                })
                .then(null, function (error) {
                    expect(error.errors).to.have.property('urlName');
                    expect(error.errors).to.have.property('user');
                    expect(error.errors).to.have.property('name');

                    done();
                });

            });

            it('should err with invalid url', function (done) {

                Store.create({
                    name: "I like basketball",
                    url: "basket/ball",
                    user: userId
                })
                .then(null, function (error) {
                    expect(error.errors).to.have.property('urlName');
                    done();
                });

            });

            it('should accept a correct store', function (done) {

                Store.create({
                    name: "I like basketball",
                    urlName: "basketball",
                    user: userId
                })
                .then(function (store) {
                    //shouldn't go here
                    expect(store.name).to.equal("I like basketball");
                    done();
                })
                .then(null, function (error) {
                    console.log(error);
                    done();
                });

            });

        });

    });

});

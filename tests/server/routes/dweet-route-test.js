var mongoose = require('mongoose');
require('../../../server/db/models');
var Dweet = mongoose.model('Dweet');
var expect = require('chai').expect;
var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var supertest = require('supertest');
var app = require('../../../server/app');

describe('Dweet Route', function () {
    beforeEach('Establish DB connection', function (done) {
		if (mongoose.connection.db) return done();
		mongoose.connect(dbURI, done);
	});

	afterEach('Clear test database', function (done) {
		clearDB(done);
	});

    describe('GET /api/data', function () {
        var agent;

        beforeEach('Create agent', function () {
			agent = supertest.agent(app);
		});

        it('should get return 500 dweets with 200 response', function (done) {
			agent.get('/api/data/')
				.expect(200)
				.end(function (err, response) {
					if (err) return done(err);
					expect(response.body).to.be.an('array');
					expect(response.body).to.be.length(500);
					done();
				});
		});
    })

    describe('GET /api/data/latest', function () {
        var agent,
            currDate;

        beforeEach('Create agent', function () {
			agent = supertest.agent(app);
		});

        it('should get return the latest dweet with 200 response', function (done) {
            currDate = new Date();

            agent.get('/api/data/latest')
				.expect(200)
				.end(function (err, response) {
					if (err) return done(err);
                    var resDate = new Date(response.body.created);
					expect(response.body.thing).to.equal('calm-patch');
                    // most recent dweet should be within the last 5 seconds
					expect(resDate.getTime()).to.be.above(currDate.getTime() - 5000);
                    expect(response.body.content.Temperature).to.be.ok;
					done();
				});
		});
    })
})

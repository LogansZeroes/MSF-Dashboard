// Instantiate all models
var mongoose = require('mongoose');
require('../../../server/db/models');
var User = mongoose.model('User');
var Store = mongoose.model('Store');


var expect = require('chai').expect;

var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var supertest = require('supertest');
var app = require('../../../server/app');

describe('Stores Route', function () {

  beforeEach('Establish DB connection', function (done) {
    if (mongoose.connection.db) return done();
    mongoose.connect(dbURI, done);
  });

  afterEach('Clear test database', function (done) {
    clearDB(done);
  });

  var testStore = {
    name: "extreme basketball",
    description: "This store is the best thing in the world for me to play basketball with.",
    urlName: "bestBasketball"
  };

  describe('GET /api/stores/', function () {

    var agent,
        userId,
        userId2;

    beforeEach('Create agent', function () {
      agent = supertest.agent(app);
    });

    beforeEach('Make 2 users', function (done) {
      User.create({email: "sean@sean.com", password: "mypass"})
      .then(function (user) {
        userId = user._id;
        testStore.user = userId;
        return User.create({email: "sean2@sean2.com", password: "mypass"});
      })
      .then(function (user) {
          userId2 = user._id;
          done();
      })
      .then(null, done);
    });

    beforeEach('Make a store', function(done) {
        Store.create(testStore)
        .then(function(){
            done();
        })
        .then(null, done);
    })


    it('should get all stores', function (done) {
      agent.get('/api/stores/')
        .expect(200)
        .end(function (err, response) {
          if (err) return done(err);
          expect(response.body).to.be.an('array');
          expect(response.body).to.be.length(1);
          done();
        });
    });

    it('should filter by user', function (done) {
      agent.get('/api/stores/')
        .query({user: userId.toString()})
        .expect(200)
        .end(function (err, response) {
          if (err) return done(err);
          expect(response.body).to.be.an('array');
          expect(response.body).to.be.length(1);
          done();
        });
    });

    it('should filter by user 2', function (done) {
      agent.get('/api/stores/')
        .query({user: userId2.toString()})
        .expect(200)
        .end(function (err, response) {
          if (err) return done(err);
          expect(response.body).to.be.an('array');
          expect(response.body).to.be.length(0);
          done();
        });
    });

  });

  describe('POST /api/stores', function () {

    var agent, userId;

    beforeEach('Create agent', function () {
      agent = supertest.agent(app);
    });

    beforeEach('Make a user', function (done) {
      User.create({email: "sean@sean.com", password: "mypass"})
      .then(function (user) {
        userId = user._id;
        testStore.user = userId;
        done();
      })
      .then(null, done);
    });


    it('should make a store', function (done) {
      agent.post('/api/stores/')
        .send(testStore)
        .expect(201)
        .end(function (err, response) {
          if (err) return done(err);
          expect(response.body.name).to.equal("extreme basketball");
          Store.find().exec()
          .then(function (stores) {
            expect(stores).to.have.length(1);
            expect(stores[0].name).to.equal("extreme basketball");
            done();
          });
        });
    });

  });

  describe('GET /api/stores/:storeId', function () {

    var agent,
        storeName,
        userId;

    beforeEach('Create agent', function () {
      agent = supertest.agent(app);
    });

    beforeEach('Make a user', function (done) {
      User.create({email: "sean@sean.com", password: "mypass"})
      .then(function (user) {
        userId = user._id;
        done();
      })
      .then(null, done);
    });

    beforeEach('Make a store', function (done) {
      testStore.user = userId;
      Store.create(testStore)
      .then(function (store) {
        storeName = store.urlName;
        done();
      })
      .then(null, function (err) {
        done();
      });
    });


    it('should get the store', function (done) {
      agent.get('/api/stores/' + storeName)
        .expect(200)
        .end(function (err, response) {
          if (err) return done(err);
          expect(response.body.name).to.equal('extreme basketball');
          done();
        });
    });

  });

  describe('PUT /api/stores/:storeId', function () {

    var agent,
        storeName,
        userId;

    beforeEach('Create agent', function () {
      agent = supertest.agent(app);
    });

    beforeEach('Make a user', function (done) {
      User.create({email: "sean@sean.com", password: "mypass"})
      .then(function (user) {
        userId = user._id;
        done();
      })
      .then(null, done);
    });

    beforeEach('Make a store', function (done) {
      testStore.user = userId;
      Store.create(testStore)
      .then(function (store) {
        storeName = store.urlName;
        done();
      })
      .then(null, function (err) {
        done();
      });
    });


    it('should edit a store', function (done) {
      agent.put('/api/stores/' + storeName)
        .send({name: "unextreme basketball"})
        .expect(201)
        .end(function (err, response) {
          if (err) return done(err);
          Store.findOne({urlName: storeName})
          .then(function (store) {
            expect(store.name).to.equal("unextreme basketball");
            done();
          });
        });
    });

  });

});

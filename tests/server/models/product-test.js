var dbURI = 'mongodb://localhost:27017/testingDB';
var clearDB = require('mocha-mongoose')(dbURI);

var sinon = require('sinon');
var expect = require('chai').expect;
var mongoose = require('mongoose');

// Require in all models.
require('../../../server/db/models');

var Product = mongoose.model('Product');
var Category = mongoose.model('Category');
var Store = mongoose.model('Store');
var User = mongoose.model('User');


describe('Product model', function () {

    var categoryId,
        storeId,
        userId;

    beforeEach('Establish DB connection', function (done) {
        if (mongoose.connection.db) return done();
        mongoose.connect(dbURI, done);
    });

    beforeEach("Create test category", function (done) {
      return Category.create({title: "Books"})
      .then(function(category){
          categoryId = category._id;
          done();
      });
    });

    beforeEach("Create test category", function (done) {
      return Category.create({title: "Default"})
      .then(function(){
          done();
      });
    });

    beforeEach("Create test user", function (done) {
      return User.create({email: "donkey@kong.com"})
      .then(function(user){
          userId = user._id;
          done();
      });
    });

    beforeEach("Create test store", function (done) {
      return Store.create({
          name: "Princess Peach Kidnapping Tools",
          urlName: "peach",
          user: userId
      })
      .then(function(store){
          storeId = store._id;
          done();
      });
    });

    beforeEach("Create test product", function () {
      return Product.create({name: "surfbort", categories: [categoryId], store: storeId});
    });

    afterEach('Clear test database', function (done) {
        clearDB(done);
    });

    it('should exist', function () {
        expect(Product).to.be.a('function');
    });

    describe('validations', function () {

      it('name should exist', function (done) {
        Product.find({}).then(function(results){
          expect(results.length).to.equal(1);
          done();
        });
      });

      it('name should be unique', function (done) {
          return Product.create({name: "surfbort", categories: [categoryId], store: storeId})
          .then(function(product){
            // shouldnt get here, sad
            done();
          })
          .then(null, function(err){
            expect(err.code).to.equal(11000);
            done();
          });
      });

      it('category should exist', function (done) {
          Product.create({name: "WMD", store: storeId})
          .then(null, function(err){
            expect(err.errors.categories).to.exist;
            done();
          });
      })

    });

});

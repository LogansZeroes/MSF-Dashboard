app.config(function($stateProvider){
  $stateProvider
  .state('user', {
    url: '/user/:userId',
    templateUrl: '/js/user/user.html',
    controller: function ($scope, findUser) {
      $scope.user = findUser;
    },
    resolve: {
      findUser: function ($stateParams, UserFactory) {
        return UserFactory.getById($stateParams.userId)
        .then(function(user){
          return user;
        });
    }
    }
  });
});

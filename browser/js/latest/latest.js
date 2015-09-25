app.config(function($stateProvider) {
    $stateProvider.state('latest', {
        url: '/data/latest',
        templateUrl: 'js/latest/latest.html',
        controller: function ($scope, latestDweet) {
          $scope.latestDweet = latestDweet;
        },
        resolve: {
            // findDweets: function (DweetFactory) {
            //     return DweetFactory.getAll();
            // };
            latestDweet: function (DweetFactory) {
                return DweetFactory.getLatest();
            }
        }
    })
})

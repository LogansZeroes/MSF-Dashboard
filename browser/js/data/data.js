app.config(function ($stateProvider) {
    $stateProvider.state('data', {
        url: '/data',
        templateUrl: 'js/data/data.html',
        controller: function ($scope, findTweets) {
          $scope.tweets = findTweets;
        },
        resolve: {
            findTweets: function (TweetFactory) {
                return TweetFactory.getAll();
            }
        }
    });
});

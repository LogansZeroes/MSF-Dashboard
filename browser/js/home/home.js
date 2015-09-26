app.config(function($stateProvider) {
    $stateProvider.state('home', {
        url: '/',
        templateUrl: 'js/home/home.html',
        controller: function($scope, DweetFactory) {
            //Create array of latest dweets to display on home state
            $scope.homeDweets = [];

            //Initialize with first dweet
            DweetFactory.getLatest()
            .then(function(dweet){
                $scope.prevDweet = dweet;
            });

            var line1 = new TimeSeries();
            var line2 = new TimeSeries();

            //Check every half second to see if the last dweet is new, then push to homeDweets, then plot
            setInterval(function() {
                DweetFactory.getLatest()
                .then(function(dweet){
                    $scope.lastDweet = dweet;
                })
                .then(function() {
                    if ($scope.prevDweet.created != $scope.lastDweet.created)
                    {
                        $scope.homeDweets.push($scope.lastDweet);
                        $scope.prevDweet = $scope.lastDweet;
                        line1.append(new Date().getTime(), $scope.lastDweet.content['Temperature']);
                        //Random plot to check that the graph is working
                        line2.append(new Date().getTime(), Math.floor(Math.random()*3+68));
                    }
                })

            }, 100);

            //Make a smoothie chart with aesthetically pleasing properties
            var smoothie = new SmoothieChart({
                grid: {
                    strokeStyle: 'rgb(63, 160, 182)',
                    fillStyle: 'rgb(4, 5, 91)',
                    lineWidth: 1,
                    millisPerLine: 500,
                    verticalSections: 4
                },
                // maxValue: 73,
                // minValue: 72,
                maxValueScale: 1.005,
                minValueScale: 1.02,
                timestampFormatter:SmoothieChart.timeFormatter,
                //The range of acceptable temperatures should be below
                horizontalLines:[{
                    color:'#880000',
                    lineWidth:2,
                    value:70
                }, {
                    color:'#880000',
                    lineWidth:2,
                    value:68
                }]
            });

            smoothie.addTimeSeries(line1, {
                strokeStyle: 'rgb(0, 255, 0)',
                fillStyle: 'rgba(0, 255, 0, 0.4)',
                lineWidth: 3
            });
            smoothie.addTimeSeries(line2, {
                strokeStyle: 'rgb(255, 0, 255)',
                fillStyle: 'rgba(255, 0, 255, 0.3)',
                lineWidth: 3
            });

            smoothie.streamTo(document.getElementById("chart"), 300);
        }
    });
});

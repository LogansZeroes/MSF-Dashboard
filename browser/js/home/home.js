app.config(function($stateProvider) {
    $stateProvider.state('home', {
        url: '/',
        templateUrl: 'js/home/home.html',
        controller: function($scope, DweetFactory, latestTemp, $rootScope, $state) {
            //Create array of latest dweets to display on home state
            $scope.homeDweets = [];
            $rootScope.homeAlerts = [];

            $scope.error = null;

            //Initialize with first dweet
            DweetFactory.getLatest()
            .then(function(dweet){
                $scope.prevDweet = dweet;
            });

            // button click leads to alerts state
            $scope.goAlerts = function () {
                $state.go('alerts');
            };

            var line1 = new TimeSeries();
            var line2 = new TimeSeries();

            // default temperature range is 50-90 for demo purposes
            if(!$rootScope.alert) {
                $rootScope.alert = {
                    upperBound: 90,
                    lowerBound: 50
                };
            }

            // Check every half second to see if the last dweet is new, then push to homeDweets, then plot
            if ($rootScope.alert) {
                setInterval(function() {
                    DweetFactory.getLatest()
                    .then(function(dweet){
                        $scope.lastDweet = dweet;
                    })
                    .then(function() {
                        var randomTemp = Math.random()*20+60;
                        if ($scope.prevDweet.created != $scope.lastDweet.created) {
                            $scope.homeDweets.push($scope.lastDweet);
                            $scope.prevDweet = $scope.lastDweet;
                            line1.append(new Date().getTime(), $scope.lastDweet.content['aiOutsideTemp_degreesF']);
                            //Random plot to check that the graph is working
                            line2.append(new Date().getTime(), randomTemp);
                        }
                        //Detect if the temperature breaks out of safe range
                        if ($scope.lastDweet.content['aiOutsideTemp_degreesF'] > $rootScope.alert.upperBound || $scope.lastDweet.content['aiOutsideTemp_degreesF'] < $rootScope.alert.lowerBound) {
                            console.log('break in cold chain')
                            var currDate = new Date();
                            var currTime = currDate.toString().slice(16);
                            $rootScope.alert.time = currTime;
                            $rootScope.alert.temp = $scope.lastDweet.content['aiOutsideTemp_degreesF'];
                            DweetFactory.postAlert($rootScope.alert)
                            .then (function (postedAlert) {
                                $rootScope.homeAlerts.push(postedAlert);
                                $scope.error = 'Break in cold chain detected!!'
                            })
                        }
                        //Detect if the temperature breaks out of safe range
            //TURN ON TO DEMONSTRATE BREAK IN COLD CHAIN ALERT & EMAIL FEATURE
                        if (randomTemp > $rootScope.alert.upperBound || randomTemp < $rootScope.alert.lowerBound) {
                            console.log('break in cold chain 2');
                            var currDate = new Date();
                            var currTime = currDate.toString().slice(16);
                            $rootScope.alert.time = currTime;
                            $rootScope.alert.temp = randomTemp;
                            DweetFactory.postAlert($rootScope.alert)
                            .then (function (postedAlert) {
                                $rootScope.homeAlerts.push(postedAlert);
                                $scope.error = 'Break in cold chain detected!!'
                            })
                        }

                        while($scope.homeDweets.length > 100) {
                            $scope.homeDweets.shift();
                        }
                        while($scope.homeAlerts.length > 100) {
                            $scope.homeAlerts.shift();
                        }
                    })
                }, 500);
            }

            //Make a smoothie chart with aesthetically pleasing properties
            var smoothie = new SmoothieChart({
                grid: {
                    strokeStyle: 'rgb(63, 160, 182)',
                    fillStyle: 'rgb(4, 5, 91)',
                    lineWidth: 1,
                    millisPerLine: 500,
                    verticalSections: 4
                },
                maxValue: $rootScope.alert.upperBound * 1.003,
                minValue: $rootScope.alert.lowerBound * 0.997,
                // maxValueScale: 1.01,
                // minValueScale: 1.02,
                timestampFormatter:SmoothieChart.timeFormatter,
                //The range of acceptable temperatures visualized
                //Should change 'value' accordingly
                horizontalLines:[{
                    color:'#880000',
                    lineWidth:5,
                    value: ($rootScope.alert.upperBound || 70)
                }, {
                    color:'#880000',
                    lineWidth:5,
                    value: ($rootScope.alert.lowerBound || 68)
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
        },
        resolve: {
            latestTemp: function (DweetFactory) {
                return DweetFactory.getLatest()
                .then( function (dweet) {
                    return dweet.content['aiOutsideTemp_degreesF'];
                });
            }
        }
    });
});

'use strict';
window.app = angular.module('MSFTemp', ['ui.router', 'ui.bootstrap', 'fsaPreBuilt']);

app.config(function ($urlRouterProvider, $locationProvider) {

    // this makes the '/users/' route correctly redirect to '/users'
    $urlRouterProvider.rule(function ($injector, $location) {

        var re = /(.+)(\/+)(\?.*)?$/;
        var path = $location.url();

        if (re.test(path)) {
            return path.replace(re, '$1$3');
        }

        return false;
    });
    // This turns off hashbang urls (/#about) and changes it to something normal (/about)
    $locationProvider.html5Mode(true);
    $urlRouterProvider.when('/auth/:provider', function () {
        window.location.reload();
    });
    // If we go to a URL that ui-router doesn't have registered, go to the "/" url.
    $urlRouterProvider.otherwise('/');
});

// This app.run is for controlling access to specific states.
app.run(function ($rootScope, AuthService, $state) {

    // The given state requires an authenticated user.
    var destinationStateRequiresAuth = function destinationStateRequiresAuth(state) {
        return state.data && state.data.authenticate;
    };

    // $stateChangeStart is an event fired
    // whenever the process of changing a state begins.
    $rootScope.$on('$stateChangeStart', function (event, toState, toParams) {

        if (!destinationStateRequiresAuth(toState)) {
            // The destination state does not require authentication
            // Short circuit with return.
            return;
        }

        if (AuthService.isAuthenticated()) {
            // The user is authenticated.
            // Short circuit with return.
            return;
        }

        // Cancel navigating to new state.
        event.preventDefault();

        AuthService.getLoggedInUser().then(function (user) {
            // If a user is retrieved, then renavigate to the destination
            // (the second time, AuthService.isAuthenticated() will work)
            // otherwise, if no user is logged in, go to "login" state.
            if (user) {
                $state.go(toState.name, toParams);
            } else {
                $state.go('login');
            }
        });
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('alerts', {
        url: '/alerts',
        templateUrl: 'js/alerts/alerts.html',
        controller: 'alertCtrl'
    });
});

app.controller('alertCtrl', function (DweetFactory, $scope, $state, $rootScope) {

    $scope.saveAlert = function (alert) {
        alert.upperBound = Number(alert.upperBound);
        alert.lowerBound = Number(alert.lowerBound);
        alert.temp;
        $rootScope.alert = alert;
        $rootScope.alertEntered = true;
        $state.go('home');
    };
});

app.config(function ($stateProvider) {
    $stateProvider.state('data', {
        url: '/data',
        templateUrl: 'js/data/data.html',
        controller: function controller($scope, allDweets) {
            $scope.dweets = allDweets;
        },
        resolve: {
            // findDweets: function (DweetFactory) {
            //     return DweetFactory.getAll();
            // };
            allDweets: function allDweets(DweetFactory) {
                return DweetFactory.getAll();
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('docs', {
        url: '/docs',
        templateUrl: 'js/docs/docs.html'
    });
});

(function () {

    'use strict';

    // Hope you didn't forget Angular! Duh-doy.
    if (!window.angular) throw new Error('I can\'t find Angular!');

    var app = angular.module('fsaPreBuilt', []);

    app.factory('Socket', function () {
        if (!window.io) throw new Error('socket.io not found!');
        return window.io(window.location.origin);
    });

    // AUTH_EVENTS is used throughout our app to
    // broadcast and listen from and to the $rootScope
    // for important events about authentication flow.
    app.constant('AUTH_EVENTS', {
        loginSuccess: 'auth-login-success',
        loginFailed: 'auth-login-failed',
        signupSuccess: 'auth-signup-success',
        signupFailed: 'auth-signup-failed',
        logoutSuccess: 'auth-logout-success',
        sessionTimeout: 'auth-session-timeout',
        notAuthenticated: 'auth-not-authenticated',
        notAuthorized: 'auth-not-authorized'
    });

    app.factory('AuthInterceptor', function ($rootScope, $q, AUTH_EVENTS) {
        var statusDict = {
            401: AUTH_EVENTS.notAuthenticated,
            403: AUTH_EVENTS.notAuthorized,
            419: AUTH_EVENTS.sessionTimeout,
            440: AUTH_EVENTS.sessionTimeout
        };
        return {
            responseError: function responseError(response) {
                $rootScope.$broadcast(statusDict[response.status], response);
                return $q.reject(response);
            }
        };
    });

    app.config(function ($httpProvider) {
        $httpProvider.interceptors.push(['$injector', function ($injector) {
            return $injector.get('AuthInterceptor');
        }]);
    });

    app.service('AuthService', function ($http, Session, $rootScope, AUTH_EVENTS, $q) {

        function onSuccessfulLogin(response) {
            var data = response.data;
            Session.create(data.id, data.user);
            $rootScope.$broadcast(AUTH_EVENTS.loginSuccess);
            return data.user;
        }

        //add successful signup
        function onSuccessfulSignup(response) {
            var data = response.data;
            Session.create(data.id, data.user);
            $rootScope.$broadcast(AUTH_EVENTS.signupSuccess);
            return data.user;
        }

        // Uses the session factory to see if an
        // authenticated user is currently registered.
        this.isAuthenticated = function () {
            return !!Session.user;
        };

        this.getLoggedInUser = function (fromServer) {

            // If an authenticated session exists, we
            // return the user attached to that session
            // with a promise. This ensures that we can
            // always interface with this method asynchronously.

            // Optionally, if true is given as the fromServer parameter,
            // then this cached value will not be used.

            if (this.isAuthenticated() && fromServer !== true) {
                return $q.when(Session.user);
            }

            // Make request GET /session.
            // If it returns a user, call onSuccessfulLogin with the response.
            // If it returns a 401 response, we catch it and instead resolve to null.
            return $http.get('/session').then(onSuccessfulLogin)['catch'](function () {
                return null;
            });
        };

        this.login = function (credentials) {
            return $http.post('/login', credentials).then(onSuccessfulLogin)['catch'](function () {
                return $q.reject({ message: 'Invalid login credentials.' });
            });
        };

        this.logout = function () {
            return $http.get('/logout').then(function () {
                Session.destroy();
                $rootScope.$broadcast(AUTH_EVENTS.logoutSuccess);
            });
        };

        this.signup = function (credentials) {
            return $http.post('/signup', credentials).then(onSuccessfulSignup);
        };
    });

    app.service('Session', function ($rootScope, AUTH_EVENTS) {

        var self = this;

        $rootScope.$on(AUTH_EVENTS.notAuthenticated, function () {
            self.destroy();
        });

        $rootScope.$on(AUTH_EVENTS.sessionTimeout, function () {
            self.destroy();
        });

        this.id = null;
        this.user = null;

        this.create = function (sessionId, user) {
            this.id = sessionId;
            this.user = user;
        };

        this.destroy = function () {
            this.id = null;
            this.user = null;
        };
    });
})();

app.config(function ($stateProvider) {
    $stateProvider.state('home', {
        url: '/',
        templateUrl: 'js/home/home.html',
        controller: function controller($scope, DweetFactory, latestTemp, $rootScope, $state) {
            //Create array of latest dweets to display on home state
            $scope.homeDweets = [];
            $rootScope.homeAlerts = [];

            $scope.error = null;

            //Initialize with first dweet
            DweetFactory.getLatest().then(function (dweet) {
                $scope.prevDweet = dweet;
            });

            // button click leads to alerts state
            $scope.goAlerts = function () {
                $state.go('alerts');
            };

            var line1 = new TimeSeries();
            var line2 = new TimeSeries();

            // default temperature range is 50-90 for demo purposes
            if (!$rootScope.alert) {
                $rootScope.alert = {
                    upperBound: 90,
                    lowerBound: 50
                };
            }

            // Check every half second to see if the last dweet is new, then push to homeDweets, then plot
            if ($rootScope.alert) {
                setInterval(function () {
                    DweetFactory.getLatest().then(function (dweet) {
                        $scope.lastDweet = dweet;
                    }).then(function () {
                        var randomTemp = Math.random() * 20 + 60;
                        if ($scope.prevDweet.created != $scope.lastDweet.created) {
                            $scope.homeDweets.push($scope.lastDweet);
                            $scope.prevDweet = $scope.lastDweet;
                            line1.append(new Date().getTime(), $scope.lastDweet.content['aiOutsideTemp_degreesF']);
                            //Random plot to check that the graph is working
                            line2.append(new Date().getTime(), randomTemp);
                        }
                        //Detect if the temperature breaks out of safe range
                        if ($scope.lastDweet.content['aiOutsideTemp_degreesF'] > $rootScope.alert.upperBound || $scope.lastDweet.content['aiOutsideTemp_degreesF'] < $rootScope.alert.lowerBound) {
                            console.log('break in cold chain');
                            var currDate = new Date();
                            var currTime = currDate.toString().slice(16);
                            $rootScope.alert.time = currTime;
                            $rootScope.alert.temp = $scope.lastDweet.content['aiOutsideTemp_degreesF'];
                            DweetFactory.postAlert($rootScope.alert).then(function (postedAlert) {
                                $rootScope.homeAlerts.push(postedAlert);
                                $scope.error = 'Break in cold chain detected!!';
                            });
                        }
                        //Detect if the temperature breaks out of safe range
                        //TURN ON TO DEMONSTRATE BREAK IN COLD CHAIN ALERT & EMAIL FEATURE
                        if (randomTemp > $rootScope.alert.upperBound || randomTemp < $rootScope.alert.lowerBound) {
                            console.log('break in cold chain 2');
                            var currDate = new Date();
                            var currTime = currDate.toString().slice(16);
                            $rootScope.alert.time = currTime;
                            $rootScope.alert.temp = randomTemp;
                            DweetFactory.postAlert($rootScope.alert).then(function (postedAlert) {
                                $rootScope.homeAlerts.push(postedAlert);
                                $scope.error = 'Break in cold chain detected!!';
                            });
                        }

                        while ($scope.homeDweets.length > 100) {
                            $scope.homeDweets.shift();
                        }
                        while ($scope.homeAlerts.length > 100) {
                            $scope.homeAlerts.shift();
                        }
                    });
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
                timestampFormatter: SmoothieChart.timeFormatter,
                //The range of acceptable temperatures visualized
                //Should change 'value' accordingly
                horizontalLines: [{
                    color: '#880000',
                    lineWidth: 5,
                    value: $rootScope.alert.upperBound || 70
                }, {
                    color: '#880000',
                    lineWidth: 5,
                    value: $rootScope.alert.lowerBound || 68
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
            latestTemp: function latestTemp(DweetFactory) {
                return DweetFactory.getLatest().then(function (dweet) {
                    return dweet.content['aiOutsideTemp_degreesF'];
                });
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('latest', {
        url: '/data/latest',
        templateUrl: 'js/latest/latest.html',
        controller: function controller($scope, latestDweet) {
            $scope.latestDweet = latestDweet;
        },
        resolve: {
            latestDweet: function latestDweet(DweetFactory) {
                return DweetFactory.getLatest();
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('login', {
        url: '/login',
        templateUrl: 'js/login/login.html',
        controller: 'LoginCtrl'
    });
});

app.controller('LoginCtrl', function ($scope, AuthService, $state) {

    $scope.login = {};
    $scope.error = null;

    $scope.sendLogin = function (loginInfo) {

        $scope.error = null;

        AuthService.login(loginInfo).then(function (user) {
            if (user.newPass) $state.go('resetPass', { 'userId': user._id });else $state.go('home');
        })['catch'](function () {
            $scope.error = 'Invalid login credentials.';
        });
    };
});

app.config(function ($stateProvider) {
    $stateProvider.state('resetPass', {
        url: '/reset/:userId',
        templateUrl: 'js/resetPass/resetPass.html',
        controller: 'ResetCtrl'
    });
});

app.controller('ResetCtrl', function ($scope, UserFactory, $stateParams, AuthService, $state) {

    $scope.resetPass = function (newPass) {
        UserFactory.edit($stateParams.userId, { 'newPass': false, 'password': newPass }).then(function (user) {
            AuthService.login({ email: user.email, password: newPass }).then(function () {
                $state.go('home');
            });
        });
    };
});

app.config(function ($stateProvider) {

    $stateProvider.state('signup', {
        url: '/signup',
        templateUrl: 'js/signup/signup.html',
        controller: 'SignupCtrl'
    });
});

app.controller('SignupCtrl', function ($scope, AuthService, $state) {

    $scope.error = null;

    $scope.sendSignup = function (signupInfo) {
        $scope.error = null;
        AuthService.signup(signupInfo).then(function () {
            $state.go('home');
        })['catch'](function () {
            $scope.error = 'Email is taken!';
        });
    };
});

app.config(function ($stateProvider) {
    $stateProvider.state('user', {
        url: '/user/:userId',
        templateUrl: '/js/user/user.html',
        controller: function controller($scope, findUser) {
            $scope.user = findUser;
        },
        resolve: {
            findUser: function findUser($stateParams, UserFactory) {
                return UserFactory.getById($stateParams.userId).then(function (user) {
                    return user;
                });
            }
        }
    });
});

app.config(function ($stateProvider) {
    $stateProvider.state('users', {
        url: '/users',
        templateUrl: '/js/users/users.html',
        resolve: {
            users: function users(UserFactory) {
                return UserFactory.getAll();
            }
        },
        controller: function controller($scope, users, Session, $state) {
            $scope.users = users;

            //WHY NOT ON SESSION????
            // if (!Session.user || !Session.user.isAdmin){
            // 	$state.go('home');
            // }
        }
    });
});

app.factory('DweetFactory', function ($http) {
    var Dweets = function Dweets(props) {
        angular.extend(this, props);
    };

    Dweets.getAll = function () {
        return $http.get('/api/data').then(function (response) {
            return response.data;
        });
    };

    Dweets.getLatest = function () {
        return $http.get('/api/data/latest').then(function (response) {
            return response.data;
        });
    };

    Dweets.postAlert = function (alert) {
        return $http.post('/api/alerts', alert).then(function (response) {
            return response.data;
        });
    };

    return Dweets;
});

app.factory('UserFactory', function ($http) {

    var User = function User(props) {
        angular.extend(this, props);
    };

    User.getAll = function () {
        return $http.get('/api/users').then(function (response) {
            return response.data;
        });
    };

    User.getById = function (id) {
        return $http.get('/api/users/' + id).then(function (response) {
            return response.data;
        });
    };

    User.edit = function (id, props) {
        return $http.put('/api/users/' + id, props).then(function (response) {
            return response.data;
        });
    };

    User['delete'] = function (id) {
        return $http['delete']('/api/users/' + id).then(function (response) {
            return response.data;
        });
    };

    return User;
});

app.directive('dweetList', function () {
    return {
        restrict: 'E',
        templateUrl: '/js/common/directives/dweet/dweet-list.html'
    };
});

app.directive("editButton", function () {
    return {
        restrict: 'EA',
        templateUrl: 'js/common/directives/edit-button/edit-button.html'
    };
});

app.directive("editPassButton", function () {
    return {
        restrict: 'EA',
        templateUrl: 'js/common/directives/edit-pass-button/edit-pass-button.html'
    };
});

app.directive('navbar', function ($rootScope, AuthService, AUTH_EVENTS, $state) {

    return {
        restrict: 'E',
        scope: {},
        templateUrl: 'js/common/directives/navbar/navbar.html',
        link: function link(scope) {

            scope.items = [{ label: 'Alerts', state: 'alerts' }, { label: 'Data', state: 'data' }, { label: 'Latest', state: 'latest' }, { label: 'Users', state: 'users' }, { label: 'Documentation', state: 'docs' }];

            scope.user = null;

            scope.isLoggedIn = function () {
                return AuthService.isAuthenticated();
            };

            scope.logout = function () {
                AuthService.logout().then(function () {
                    $state.go('home');
                });
            };

            var setUser = function setUser() {
                AuthService.getLoggedInUser().then(function (user) {
                    scope.user = user;
                });
            };

            var removeUser = function removeUser() {
                scope.user = null;
            };

            setUser();

            $rootScope.$on(AUTH_EVENTS.loginSuccess, setUser);
            $rootScope.$on(AUTH_EVENTS.signupSuccess, setUser);
            $rootScope.$on(AUTH_EVENTS.logoutSuccess, removeUser);
            $rootScope.$on(AUTH_EVENTS.sessionTimeout, removeUser);
        }

    };
});

app.directive('userDetail', function (UserFactory, $stateParams, $state, Session) {
    return {
        restrict: 'E',
        templateUrl: '/js/common/directives/user/user-detail/user-detail.html',
        link: function link(scope) {
            scope.isDetail = true;
            scope.isAdmin = Session.user.isAdmin;
            scope.editMode = false;
            scope.editPass = false;

            //FIX THIS LINE
            if (scope.user = Session.user) scope.isOwner = true;

            scope.enableEdit = function () {
                scope.cached = angular.copy(scope.user);
                scope.editMode = true;
            };
            scope.cancelEdit = function () {
                scope.user = angular.copy(scope.cached);
                scope.editMode = false;
                scope.editPass = false;
            };
            scope.saveUser = function (user) {
                UserFactory.edit(user._id, user).then(function (updatedUser) {
                    scope.user = updatedUser;
                    scope.editMode = false;
                    scope.editPass = false;
                });
            };
            scope.deleteUser = function (user) {
                UserFactory['delete'](user).then(function () {
                    scope.editMode = false;
                    scope.editPass = false;
                    $state.go('home');
                });
            };

            scope.passwordEdit = function () {
                // UserFactory.edit(id, {'newPass': true})
                // .then(function () {
                //     // scope.newPass = true;
                //     scope.editMode = false;
                // });
                scope.cached = angular.copy(scope.user);
                scope.editPass = true;
            };
        },
        scope: {
            user: "="
        }
    };
});

app.directive('userList', function () {
    return {
        restrict: 'E',
        templateUrl: '/js/common/directives/user/user-list/user-list.html'
    };
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFsZXJ0cy9hbGVydHMuanMiLCJkYXRhL2RhdGEuanMiLCJkb2NzL2RvY3MuanMiLCJmc2EvZnNhLXByZS1idWlsdC5qcyIsImhvbWUvaG9tZS5qcyIsImxhdGVzdC9sYXRlc3QuanMiLCJsb2dpbi9sb2dpbi5qcyIsInJlc2V0UGFzcy9yZXNldFBhc3MuanMiLCJzaWdudXAvc2lnbnVwLmpzIiwidXNlci91c2VyLmpzIiwidXNlcnMvdXNlcnMuanMiLCJjb21tb24vZmFjdG9yaWVzL2R3ZWV0LWZhY3RvcnkuanMiLCJjb21tb24vZmFjdG9yaWVzL3VzZXItZmFjdG9yeS5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2R3ZWV0L2R3ZWV0LWxpc3QuanMiLCJjb21tb24vZGlyZWN0aXZlcy9lZGl0LWJ1dHRvbi9lZGl0LWJ1dHRvbi5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2VkaXQtcGFzcy1idXR0b24vZWRpdC1wYXNzLWJ1dHRvbi5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItZGV0YWlsL3VzZXItZGV0YWlsLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWxpc3QvdXNlci1saXN0LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLFlBQUEsQ0FBQTtBQUNBLE1BQUEsQ0FBQSxHQUFBLEdBQUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxTQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLGFBQUEsQ0FBQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7O0FBR0Esc0JBQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBOztBQUVBLFlBQUEsRUFBQSxHQUFBLG1CQUFBLENBQUE7QUFDQSxZQUFBLElBQUEsR0FBQSxTQUFBLENBQUEsR0FBQSxFQUFBLENBQUE7O0FBRUEsWUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLE9BQUEsQ0FBQSxFQUFBLEVBQUEsTUFBQSxDQUFBLENBQUE7U0FDQTs7QUFFQSxlQUFBLEtBQUEsQ0FBQTtLQUNBLENBQUEsQ0FBQTs7QUFFQSxxQkFBQSxDQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsWUFBQTtBQUNBLGNBQUEsQ0FBQSxRQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsc0JBQUEsQ0FBQSxTQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7OztBQUdBLEdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7O0FBR0EsUUFBQSw0QkFBQSxHQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxJQUFBLElBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxZQUFBLENBQUE7S0FDQSxDQUFBOzs7O0FBSUEsY0FBQSxDQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDRCQUFBLENBQUEsT0FBQSxDQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7O0FBRUEsWUFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7OztBQUdBLGFBQUEsQ0FBQSxjQUFBLEVBQUEsQ0FBQTs7QUFFQSxtQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTs7OztBQUlBLGdCQUFBLElBQUEsRUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxNQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsT0FBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUEsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUNuRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxTQUFBO0FBQ0EsbUJBQUEsRUFBQSx1QkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLFVBQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsYUFBQSxDQUFBLFVBQUEsR0FBQSxNQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxDQUFBLFVBQUEsR0FBQSxNQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLGtCQUFBLENBQUEsWUFBQSxHQUFBLElBQUEsQ0FBQTtBQUNBLGNBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2xCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLE9BQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxNQUFBLEdBQUEsU0FBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7Ozs7QUFJQSxxQkFBQSxFQUFBLG1CQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLFlBQUEsQ0FBQSxNQUFBLEVBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDakJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsT0FBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsQ0FBQSxZQUFBOztBQUVBLGdCQUFBLENBQUE7OztBQUdBLFFBQUEsQ0FBQSxNQUFBLENBQUEsT0FBQSxFQUFBLE1BQUEsSUFBQSxLQUFBLENBQUEsd0JBQUEsQ0FBQSxDQUFBOztBQUVBLFFBQUEsR0FBQSxHQUFBLE9BQUEsQ0FBQSxNQUFBLENBQUEsYUFBQSxFQUFBLEVBQUEsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxPQUFBLENBQUEsUUFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLENBQUEsTUFBQSxDQUFBLEVBQUEsRUFBQSxNQUFBLElBQUEsS0FBQSxDQUFBLHNCQUFBLENBQUEsQ0FBQTtBQUNBLGVBQUEsTUFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQSxDQUFBOzs7OztBQUtBLE9BQUEsQ0FBQSxRQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7QUFDQSxxQkFBQSxFQUFBLHFCQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7QUFDQSxzQkFBQSxFQUFBLHNCQUFBO0FBQ0Esd0JBQUEsRUFBQSx3QkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsVUFBQSxFQUFBLEVBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsRUFBQSxXQUFBLENBQUEsZ0JBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGFBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7U0FDQSxDQUFBO0FBQ0EsZUFBQTtBQUNBLHlCQUFBLEVBQUEsdUJBQUEsUUFBQSxFQUFBO0FBQ0EsMEJBQUEsQ0FBQSxVQUFBLENBQUEsVUFBQSxDQUFBLFFBQUEsQ0FBQSxNQUFBLENBQUEsRUFBQSxRQUFBLENBQUEsQ0FBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLHFCQUFBLENBQUEsWUFBQSxDQUFBLElBQUEsQ0FBQSxDQUNBLFdBQUEsRUFDQSxVQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsQ0FBQSxHQUFBLENBQUEsaUJBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsRUFBQSxFQUFBOztBQUVBLGlCQUFBLGlCQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsRUFBQSxFQUFBLElBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQTs7O0FBR0EsaUJBQUEsa0JBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLEdBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBLEVBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBOzs7O0FBSUEsWUFBQSxDQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsQ0FBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxlQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7Ozs7Ozs7Ozs7QUFVQSxnQkFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLElBQUEsVUFBQSxLQUFBLElBQUEsRUFBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO2FBQ0E7Ozs7O0FBS0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsaUJBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUVBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsUUFBQSxFQUFBLFdBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxpQkFBQSxDQUFBLFNBQ0EsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxFQUFBLE9BQUEsRUFBQSw0QkFBQSxFQUFBLENBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7QUFDQSwwQkFBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsa0JBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQTtLQUdBLENBQUEsQ0FBQTs7QUFFQSxPQUFBLENBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxJQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxnQkFBQSxFQUFBLFlBQUE7QUFDQSxnQkFBQSxDQUFBLE9BQUEsRUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxjQUFBLEVBQUEsWUFBQTtBQUNBLGdCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEVBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxZQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxZQUFBLENBQUEsTUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLENBQUEsRUFBQSxHQUFBLFNBQUEsQ0FBQTtBQUNBLGdCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxFQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsRUFBQSxDQUFBOztBQ3BKQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFVBQUEsRUFBQSxVQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLGtCQUFBLENBQUEsVUFBQSxHQUFBLEVBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxHQUFBLEVBQUEsQ0FBQTs7QUFFQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7OztBQUdBLHdCQUFBLENBQUEsU0FBQSxFQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0Esc0JBQUEsQ0FBQSxTQUFBLEdBQUEsS0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOzs7QUFHQSxrQkFBQSxDQUFBLFFBQUEsR0FBQSxZQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGdCQUFBLEtBQUEsR0FBQSxJQUFBLFVBQUEsRUFBQSxDQUFBO0FBQ0EsZ0JBQUEsS0FBQSxHQUFBLElBQUEsVUFBQSxFQUFBLENBQUE7OztBQUdBLGdCQUFBLENBQUEsVUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDBCQUFBLENBQUEsS0FBQSxHQUFBO0FBQ0EsOEJBQUEsRUFBQSxFQUFBO0FBQ0EsOEJBQUEsRUFBQSxFQUFBO2lCQUNBLENBQUE7YUFDQTs7O0FBR0EsZ0JBQUEsVUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLENBQUEsWUFBQTtBQUNBLGdDQUFBLENBQUEsU0FBQSxFQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsOEJBQUEsQ0FBQSxTQUFBLEdBQUEsS0FBQSxDQUFBO3FCQUNBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLDRCQUFBLFVBQUEsR0FBQSxJQUFBLENBQUEsTUFBQSxFQUFBLEdBQUEsRUFBQSxHQUFBLEVBQUEsQ0FBQTtBQUNBLDRCQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxJQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0Esa0NBQUEsQ0FBQSxVQUFBLENBQUEsSUFBQSxDQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQTtBQUNBLGtDQUFBLENBQUEsU0FBQSxHQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUE7QUFDQSxpQ0FBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLElBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLHdCQUFBLENBQUEsQ0FBQSxDQUFBOztBQUVBLGlDQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsSUFBQSxFQUFBLENBQUEsT0FBQSxFQUFBLEVBQUEsVUFBQSxDQUFBLENBQUE7eUJBQ0E7O0FBRUEsNEJBQUEsTUFBQSxDQUFBLFNBQUEsQ0FBQSxPQUFBLENBQUEsd0JBQUEsQ0FBQSxHQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxJQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLHdCQUFBLENBQUEsR0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsRUFBQTtBQUNBLG1DQUFBLENBQUEsR0FBQSxDQUFBLHFCQUFBLENBQUEsQ0FBQTtBQUNBLGdDQUFBLFFBQUEsR0FBQSxJQUFBLElBQUEsRUFBQSxDQUFBO0FBQ0EsZ0NBQUEsUUFBQSxHQUFBLFFBQUEsQ0FBQSxRQUFBLEVBQUEsQ0FBQSxLQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7QUFDQSxzQ0FBQSxDQUFBLEtBQUEsQ0FBQSxJQUFBLEdBQUEsUUFBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxHQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLHdCQUFBLENBQUEsQ0FBQTtBQUNBLHdDQUFBLENBQUEsU0FBQSxDQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSwwQ0FBQSxDQUFBLFVBQUEsQ0FBQSxJQUFBLENBQUEsV0FBQSxDQUFBLENBQUE7QUFDQSxzQ0FBQSxDQUFBLEtBQUEsR0FBQSxnQ0FBQSxDQUFBOzZCQUNBLENBQUEsQ0FBQTt5QkFDQTs7O0FBR0EsNEJBQUEsVUFBQSxHQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxJQUFBLFVBQUEsR0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsRUFBQTtBQUNBLG1DQUFBLENBQUEsR0FBQSxDQUFBLHVCQUFBLENBQUEsQ0FBQTtBQUNBLGdDQUFBLFFBQUEsR0FBQSxJQUFBLElBQUEsRUFBQSxDQUFBO0FBQ0EsZ0NBQUEsUUFBQSxHQUFBLFFBQUEsQ0FBQSxRQUFBLEVBQUEsQ0FBQSxLQUFBLENBQUEsRUFBQSxDQUFBLENBQUE7QUFDQSxzQ0FBQSxDQUFBLEtBQUEsQ0FBQSxJQUFBLEdBQUEsUUFBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxHQUFBLFVBQUEsQ0FBQTtBQUNBLHdDQUFBLENBQUEsU0FBQSxDQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSwwQ0FBQSxDQUFBLFVBQUEsQ0FBQSxJQUFBLENBQUEsV0FBQSxDQUFBLENBQUE7QUFDQSxzQ0FBQSxDQUFBLEtBQUEsR0FBQSxnQ0FBQSxDQUFBOzZCQUNBLENBQUEsQ0FBQTt5QkFDQTs7QUFFQSwrQkFBQSxNQUFBLENBQUEsVUFBQSxDQUFBLE1BQUEsR0FBQSxHQUFBLEVBQUE7QUFDQSxrQ0FBQSxDQUFBLFVBQUEsQ0FBQSxLQUFBLEVBQUEsQ0FBQTt5QkFDQTtBQUNBLCtCQUFBLE1BQUEsQ0FBQSxVQUFBLENBQUEsTUFBQSxHQUFBLEdBQUEsRUFBQTtBQUNBLGtDQUFBLENBQUEsVUFBQSxDQUFBLEtBQUEsRUFBQSxDQUFBO3lCQUNBO3FCQUNBLENBQUEsQ0FBQTtpQkFDQSxFQUFBLEdBQUEsQ0FBQSxDQUFBO2FBQ0E7OztBQUdBLGdCQUFBLFFBQUEsR0FBQSxJQUFBLGFBQUEsQ0FBQTtBQUNBLG9CQUFBLEVBQUE7QUFDQSwrQkFBQSxFQUFBLG1CQUFBO0FBQ0EsNkJBQUEsRUFBQSxlQUFBO0FBQ0EsNkJBQUEsRUFBQSxDQUFBO0FBQ0EsaUNBQUEsRUFBQSxHQUFBO0FBQ0Esb0NBQUEsRUFBQSxDQUFBO2lCQUNBO0FBQ0Esd0JBQUEsRUFBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsR0FBQSxLQUFBO0FBQ0Esd0JBQUEsRUFBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsR0FBQSxLQUFBOzs7QUFHQSxrQ0FBQSxFQUFBLGFBQUEsQ0FBQSxhQUFBOzs7QUFHQSwrQkFBQSxFQUFBLENBQUE7QUFDQSx5QkFBQSxFQUFBLFNBQUE7QUFDQSw2QkFBQSxFQUFBLENBQUE7QUFDQSx5QkFBQSxFQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7aUJBQ0EsRUFBQTtBQUNBLHlCQUFBLEVBQUEsU0FBQTtBQUNBLDZCQUFBLEVBQUEsQ0FBQTtBQUNBLHlCQUFBLEVBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtpQkFDQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOztBQUVBLG9CQUFBLENBQUEsYUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLEVBQUEsZ0JBQUE7QUFDQSx5QkFBQSxFQUFBLHNCQUFBO0FBQ0EseUJBQUEsRUFBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBO0FBQ0Esb0JBQUEsQ0FBQSxhQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsMkJBQUEsRUFBQSxrQkFBQTtBQUNBLHlCQUFBLEVBQUEsd0JBQUE7QUFDQSx5QkFBQSxFQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7O0FBRUEsb0JBQUEsQ0FBQSxRQUFBLENBQUEsUUFBQSxDQUFBLGNBQUEsQ0FBQSxPQUFBLENBQUEsRUFBQSxHQUFBLENBQUEsQ0FBQTtTQUNBO0FBQ0EsZUFBQSxFQUFBO0FBQ0Esc0JBQUEsRUFBQSxvQkFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLENBQUEsU0FBQSxFQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsMkJBQUEsS0FBQSxDQUFBLE9BQUEsQ0FBQSx3QkFBQSxDQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0E7U0FDQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUN4SUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxjQUFBO0FBQ0EsbUJBQUEsRUFBQSx1QkFBQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsV0FBQSxHQUFBLFdBQUEsQ0FBQTtTQUNBO0FBQ0EsZUFBQSxFQUFBO0FBQ0EsdUJBQUEsRUFBQSxxQkFBQSxZQUFBLEVBQUE7QUFDQSx1QkFBQSxZQUFBLENBQUEsU0FBQSxFQUFBLENBQUE7YUFDQTtTQUNBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2JBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsUUFBQTtBQUNBLG1CQUFBLEVBQUEscUJBQUE7QUFDQSxrQkFBQSxFQUFBLFdBQUE7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsS0FBQSxHQUFBLEVBQUEsQ0FBQTtBQUNBLFVBQUEsQ0FBQSxLQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLFVBQUEsQ0FBQSxTQUFBLEdBQUEsVUFBQSxTQUFBLEVBQUE7O0FBRUEsY0FBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsbUJBQUEsQ0FBQSxLQUFBLENBQUEsU0FBQSxDQUFBLENBQUEsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxDQUFBLE9BQUEsRUFBQSxNQUFBLENBQUEsRUFBQSxDQUFBLFdBQUEsRUFBQSxFQUFBLFFBQUEsRUFBQSxJQUFBLENBQUEsR0FBQSxFQUFBLENBQUEsQ0FBQSxLQUNBLE1BQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7U0FDQSxDQUFBLFNBQUEsQ0FBQSxZQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLEdBQUEsNEJBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDeEJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUNBLEtBQUEsQ0FBQSxXQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsZ0JBQUE7QUFDQSxtQkFBQSxFQUFBLDZCQUFBO0FBQ0Esa0JBQUEsRUFBQSxXQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQUVBLEdBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsT0FBQSxFQUFBO0FBQ0EsbUJBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQSxDQUFBLE1BQUEsRUFBQSxFQUFBLFNBQUEsRUFBQSxLQUFBLEVBQUEsVUFBQSxFQUFBLE9BQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsdUJBQUEsQ0FBQSxLQUFBLENBQUEsRUFBQSxLQUFBLEVBQUEsSUFBQSxDQUFBLEtBQUEsRUFBQSxRQUFBLEVBQUEsT0FBQSxFQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNwQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTs7QUFFQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsU0FBQTtBQUNBLG1CQUFBLEVBQUEsdUJBQUE7QUFDQSxrQkFBQSxFQUFBLFlBQUE7S0FDQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLFVBQUEsQ0FBQSxZQUFBLEVBQUEsVUFBQSxNQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxVQUFBLENBQUEsVUFBQSxHQUFBLFVBQUEsVUFBQSxFQUFBO0FBQ0EsY0FBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxTQUNBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLGlCQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FFQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQzFCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLGVBQUE7QUFDQSxtQkFBQSxFQUFBLG9CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsUUFBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxJQUFBLEdBQUEsUUFBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7QUFDQSxvQkFBQSxFQUFBLGtCQUFBLFlBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsT0FBQSxDQUFBLFlBQUEsQ0FBQSxNQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7QUFDQSwyQkFBQSxJQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0E7U0FDQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNqQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxRQUFBO0FBQ0EsbUJBQUEsRUFBQSxzQkFBQTtBQUNBLGVBQUEsRUFBQTtBQUNBLGlCQUFBLEVBQUEsZUFBQSxXQUFBLEVBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7YUFDQTtTQUNBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxNQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxLQUFBLENBQUE7Ozs7OztTQU1BO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2xCQSxHQUFBLENBQUEsT0FBQSxDQUFBLGNBQUEsRUFBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLFFBQUEsTUFBQSxHQUFBLFNBQUEsTUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxVQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLGtCQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLGFBQUEsRUFBQSxLQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxXQUFBLE1BQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUMzQkEsR0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7O0FBRUEsUUFBQSxJQUFBLEdBQUEsU0FBQSxJQUFBLENBQUEsS0FBQSxFQUFBO0FBQ0EsZUFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLEVBQUEsS0FBQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFFBQUEsQ0FBQSxNQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsT0FBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLGFBQUEsR0FBQSxFQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsSUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFFBQUEsVUFBQSxHQUFBLFVBQUEsRUFBQSxFQUFBO0FBQ0EsZUFBQSxLQUFBLFVBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBR0EsV0FBQSxJQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDcENBLEdBQUEsQ0FBQSxTQUFBLENBQUEsV0FBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsbUJBQUEsRUFBQSw2Q0FBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxZQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLElBQUE7QUFDQSxtQkFBQSxFQUFBLG1EQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNMQSxHQUFBLENBQUEsU0FBQSxDQUFBLGdCQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLElBQUE7QUFDQSxtQkFBQSxFQUFBLDZEQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNMQSxHQUFBLENBQUEsU0FBQSxDQUFBLFFBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7QUFFQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsYUFBQSxFQUFBLEVBQUE7QUFDQSxtQkFBQSxFQUFBLHlDQUFBO0FBQ0EsWUFBQSxFQUFBLGNBQUEsS0FBQSxFQUFBOztBQUVBLGlCQUFBLENBQUEsS0FBQSxHQUFBLENBQ0EsRUFBQSxLQUFBLEVBQUEsUUFBQSxFQUFBLEtBQUEsRUFBQSxRQUFBLEVBQUEsRUFDQSxFQUFBLEtBQUEsRUFBQSxNQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQSxFQUNBLEVBQUEsS0FBQSxFQUFBLFFBQUEsRUFBQSxLQUFBLEVBQUEsUUFBQSxFQUFBLEVBQ0EsRUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsRUFDQSxFQUFBLEtBQUEsRUFBQSxlQUFBLEVBQUEsS0FBQSxFQUFBLE1BQUEsRUFBQSxDQUNBLENBQUE7O0FBRUEsaUJBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLGlCQUFBLENBQUEsVUFBQSxHQUFBLFlBQUE7QUFDQSx1QkFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGlCQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSwyQkFBQSxDQUFBLE1BQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxZQUFBO0FBQ0EsMEJBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0EsQ0FBQTs7QUFFQSxnQkFBQSxPQUFBLEdBQUEsU0FBQSxPQUFBLEdBQUE7QUFDQSwyQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLHlCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtpQkFDQSxDQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGdCQUFBLFVBQUEsR0FBQSxTQUFBLFVBQUEsR0FBQTtBQUNBLHFCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTthQUNBLENBQUE7O0FBRUEsbUJBQUEsRUFBQSxDQUFBOztBQUVBLHNCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxZQUFBLEVBQUEsT0FBQSxDQUFBLENBQUE7QUFDQSxzQkFBQSxDQUFBLEdBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxFQUFBLE9BQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxHQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsRUFBQSxVQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxDQUFBLENBQUE7U0FFQTs7S0FFQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQ2pEQSxHQUFBLENBQUEsU0FBQSxDQUFBLFlBQUEsRUFBQSxVQUFBLFdBQUEsRUFBQSxZQUFBLEVBQUEsTUFBQSxFQUFBLE9BQUEsRUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLHlEQUFBO0FBQ0EsWUFBQSxFQUFBLGNBQUEsS0FBQSxFQUFBO0FBQ0EsaUJBQUEsQ0FBQSxRQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxPQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxPQUFBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7OztBQUdBLGdCQUFBLEtBQUEsQ0FBQSxJQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsRUFBQSxLQUFBLENBQUEsT0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxpQkFBQSxDQUFBLFVBQUEsR0FBQSxZQUFBO0FBQ0EscUJBQUEsQ0FBQSxNQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxDQUFBLENBQUE7QUFDQSxxQkFBQSxDQUFBLFFBQUEsR0FBQSxJQUFBLENBQUE7YUFDQSxDQUFBO0FBQ0EsaUJBQUEsQ0FBQSxVQUFBLEdBQUEsWUFBQTtBQUNBLHFCQUFBLENBQUEsSUFBQSxHQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUEsS0FBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO0FBQ0EscUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EscUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO2FBQ0EsQ0FBQTtBQUNBLGlCQUFBLENBQUEsUUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMkJBQUEsQ0FBQSxJQUFBLENBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxJQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSx5QkFBQSxDQUFBLElBQUEsR0FBQSxXQUFBLENBQUE7QUFDQSx5QkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7QUFDQSx5QkFBQSxDQUFBLFFBQUEsR0FBQSxLQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0EsQ0FBQTtBQUNBLGlCQUFBLENBQUEsVUFBQSxHQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMkJBQUEsVUFBQSxDQUFBLElBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxZQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EsMEJBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7aUJBQ0EsQ0FBQSxDQUFBO2FBQ0EsQ0FBQTs7QUFFQSxpQkFBQSxDQUFBLFlBQUEsR0FBQSxZQUFBOzs7Ozs7QUFNQSxxQkFBQSxDQUFBLE1BQUEsR0FBQSxPQUFBLENBQUEsSUFBQSxDQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHFCQUFBLENBQUEsUUFBQSxHQUFBLElBQUEsQ0FBQTthQUNBLENBQUE7U0FDQTtBQUNBLGFBQUEsRUFBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtTQUNBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNyREEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLEVBQUEsWUFBQTtBQUNBLFdBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLHFEQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQSIsImZpbGUiOiJtYWluLmpzIiwic291cmNlc0NvbnRlbnQiOlsiJ3VzZSBzdHJpY3QnO1xud2luZG93LmFwcCA9IGFuZ3VsYXIubW9kdWxlKCdNU0ZUZW1wJywgWyd1aS5yb3V0ZXInLCAndWkuYm9vdHN0cmFwJywgJ2ZzYVByZUJ1aWx0J10pO1xuXG5hcHAuY29uZmlnKGZ1bmN0aW9uICgkdXJsUm91dGVyUHJvdmlkZXIsICRsb2NhdGlvblByb3ZpZGVyKSB7XG5cblx0Ly8gdGhpcyBtYWtlcyB0aGUgJy91c2Vycy8nIHJvdXRlIGNvcnJlY3RseSByZWRpcmVjdCB0byAnL3VzZXJzJ1xuXHQkdXJsUm91dGVyUHJvdmlkZXIucnVsZShmdW5jdGlvbiAoJGluamVjdG9yLCAkbG9jYXRpb24pIHtcblxuXHRcdHZhciByZSA9IC8oLispKFxcLyspKFxcPy4qKT8kL1xuXHRcdHZhciBwYXRoID0gJGxvY2F0aW9uLnVybCgpO1xuXG5cdFx0aWYocmUudGVzdChwYXRoKSkge1xuXHRcdFx0cmV0dXJuIHBhdGgucmVwbGFjZShyZSwgJyQxJDMnKVxuXHRcdH1cblxuXHRcdHJldHVybiBmYWxzZTtcblx0fSk7XG5cdC8vIFRoaXMgdHVybnMgb2ZmIGhhc2hiYW5nIHVybHMgKC8jYWJvdXQpIGFuZCBjaGFuZ2VzIGl0IHRvIHNvbWV0aGluZyBub3JtYWwgKC9hYm91dClcblx0JGxvY2F0aW9uUHJvdmlkZXIuaHRtbDVNb2RlKHRydWUpO1xuXHQkdXJsUm91dGVyUHJvdmlkZXIud2hlbignL2F1dGgvOnByb3ZpZGVyJywgZnVuY3Rpb24gKCkge1xuXHRcdHdpbmRvdy5sb2NhdGlvbi5yZWxvYWQoKTtcblx0fSk7XG5cdC8vIElmIHdlIGdvIHRvIGEgVVJMIHRoYXQgdWktcm91dGVyIGRvZXNuJ3QgaGF2ZSByZWdpc3RlcmVkLCBnbyB0byB0aGUgXCIvXCIgdXJsLlxuXHQkdXJsUm91dGVyUHJvdmlkZXIub3RoZXJ3aXNlKCcvJyk7XG5cbn0pO1xuXG4vLyBUaGlzIGFwcC5ydW4gaXMgZm9yIGNvbnRyb2xsaW5nIGFjY2VzcyB0byBzcGVjaWZpYyBzdGF0ZXMuXG5hcHAucnVuKGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cblx0Ly8gVGhlIGdpdmVuIHN0YXRlIHJlcXVpcmVzIGFuIGF1dGhlbnRpY2F0ZWQgdXNlci5cblx0dmFyIGRlc3RpbmF0aW9uU3RhdGVSZXF1aXJlc0F1dGggPSBmdW5jdGlvbiAoc3RhdGUpIHtcblx0XHRyZXR1cm4gc3RhdGUuZGF0YSAmJiBzdGF0ZS5kYXRhLmF1dGhlbnRpY2F0ZTtcblx0fTtcblxuXHQvLyAkc3RhdGVDaGFuZ2VTdGFydCBpcyBhbiBldmVudCBmaXJlZFxuXHQvLyB3aGVuZXZlciB0aGUgcHJvY2VzcyBvZiBjaGFuZ2luZyBhIHN0YXRlIGJlZ2lucy5cblx0JHJvb3RTY29wZS4kb24oJyRzdGF0ZUNoYW5nZVN0YXJ0JywgZnVuY3Rpb24gKGV2ZW50LCB0b1N0YXRlLCB0b1BhcmFtcykge1xuXG5cdFx0aWYgKCFkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoKHRvU3RhdGUpKSB7XG5cdFx0XHQvLyBUaGUgZGVzdGluYXRpb24gc3RhdGUgZG9lcyBub3QgcmVxdWlyZSBhdXRoZW50aWNhdGlvblxuXHRcdFx0Ly8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cblx0XHRcdHJldHVybjtcblx0XHR9XG5cblx0XHRpZiAoQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkpIHtcblx0XHRcdC8vIFRoZSB1c2VyIGlzIGF1dGhlbnRpY2F0ZWQuXG5cdFx0XHQvLyBTaG9ydCBjaXJjdWl0IHdpdGggcmV0dXJuLlxuXHRcdFx0cmV0dXJuO1xuXHRcdH1cblxuXHRcdC8vIENhbmNlbCBuYXZpZ2F0aW5nIHRvIG5ldyBzdGF0ZS5cblx0XHRldmVudC5wcmV2ZW50RGVmYXVsdCgpO1xuXG5cdFx0QXV0aFNlcnZpY2UuZ2V0TG9nZ2VkSW5Vc2VyKCkudGhlbihmdW5jdGlvbiAodXNlcikge1xuXHRcdFx0Ly8gSWYgYSB1c2VyIGlzIHJldHJpZXZlZCwgdGhlbiByZW5hdmlnYXRlIHRvIHRoZSBkZXN0aW5hdGlvblxuXHRcdFx0Ly8gKHRoZSBzZWNvbmQgdGltZSwgQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCkgd2lsbCB3b3JrKVxuXHRcdFx0Ly8gb3RoZXJ3aXNlLCBpZiBubyB1c2VyIGlzIGxvZ2dlZCBpbiwgZ28gdG8gXCJsb2dpblwiIHN0YXRlLlxuXHRcdFx0aWYgKHVzZXIpIHtcblx0XHRcdFx0JHN0YXRlLmdvKHRvU3RhdGUubmFtZSwgdG9QYXJhbXMpO1xuXHRcdFx0fSBlbHNlIHtcblx0XHRcdFx0JHN0YXRlLmdvKCdsb2dpbicpO1xuXHRcdFx0fVxuXHRcdH0pO1xuXG5cdH0pO1xuXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2FsZXJ0cycsIHtcbiAgICAgICAgdXJsOiAnL2FsZXJ0cycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvYWxlcnRzL2FsZXJ0cy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ2FsZXJ0Q3RybCdcbiAgICB9KVxufSlcblxuYXBwLmNvbnRyb2xsZXIoJ2FsZXJ0Q3RybCcsIGZ1bmN0aW9uIChEd2VldEZhY3RvcnksICRzY29wZSwgJHN0YXRlLCAkcm9vdFNjb3BlKSB7XG5cbiAgICAkc2NvcGUuc2F2ZUFsZXJ0ID0gZnVuY3Rpb24gKGFsZXJ0KSB7XG4gICAgICAgIGFsZXJ0LnVwcGVyQm91bmQgPSBOdW1iZXIoYWxlcnQudXBwZXJCb3VuZCk7XG4gICAgICAgIGFsZXJ0Lmxvd2VyQm91bmQgPSBOdW1iZXIoYWxlcnQubG93ZXJCb3VuZCk7XG4gICAgICAgIGFsZXJ0LnRlbXA7XG4gICAgICAgICRyb290U2NvcGUuYWxlcnQgPSBhbGVydDtcbiAgICAgICAgJHJvb3RTY29wZS5hbGVydEVudGVyZWQgPSB0cnVlO1xuICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICB9XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgIC5zdGF0ZSgnZGF0YScsIHtcbiAgICAgICAgdXJsOiAnL2RhdGEnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2RhdGEvZGF0YS5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgYWxsRHdlZXRzKSB7XG4gICAgICAgICAgJHNjb3BlLmR3ZWV0cyA9IGFsbER3ZWV0cztcbiAgICAgICAgfSxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgLy8gZmluZER3ZWV0czogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgLy8gICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0QWxsKCk7XG4gICAgICAgICAgICAvLyB9O1xuICAgICAgICAgICAgYWxsRHdlZXRzOiBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIER3ZWV0RmFjdG9yeS5nZXRBbGwoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pXG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2RvY3MnLCB7XG4gICAgICAgIHVybDogJy9kb2NzJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kb2NzL2RvY3MuaHRtbCdcbiAgICB9KTtcbn0pO1xuIiwiKGZ1bmN0aW9uICgpIHtcblxuICAgICd1c2Ugc3RyaWN0JztcblxuICAgIC8vIEhvcGUgeW91IGRpZG4ndCBmb3JnZXQgQW5ndWxhciEgRHVoLWRveS5cbiAgICBpZiAoIXdpbmRvdy5hbmd1bGFyKSB0aHJvdyBuZXcgRXJyb3IoJ0kgY2FuXFwndCBmaW5kIEFuZ3VsYXIhJyk7XG5cbiAgICB2YXIgYXBwID0gYW5ndWxhci5tb2R1bGUoJ2ZzYVByZUJ1aWx0JywgW10pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ1NvY2tldCcsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgaWYgKCF3aW5kb3cuaW8pIHRocm93IG5ldyBFcnJvcignc29ja2V0LmlvIG5vdCBmb3VuZCEnKTtcbiAgICAgICAgcmV0dXJuIHdpbmRvdy5pbyh3aW5kb3cubG9jYXRpb24ub3JpZ2luKTtcbiAgICB9KTtcblxuICAgIC8vIEFVVEhfRVZFTlRTIGlzIHVzZWQgdGhyb3VnaG91dCBvdXIgYXBwIHRvXG4gICAgLy8gYnJvYWRjYXN0IGFuZCBsaXN0ZW4gZnJvbSBhbmQgdG8gdGhlICRyb290U2NvcGVcbiAgICAvLyBmb3IgaW1wb3J0YW50IGV2ZW50cyBhYm91dCBhdXRoZW50aWNhdGlvbiBmbG93LlxuICAgIGFwcC5jb25zdGFudCgnQVVUSF9FVkVOVFMnLCB7XG4gICAgICAgIGxvZ2luU3VjY2VzczogJ2F1dGgtbG9naW4tc3VjY2VzcycsXG4gICAgICAgIGxvZ2luRmFpbGVkOiAnYXV0aC1sb2dpbi1mYWlsZWQnLFxuICAgICAgICBzaWdudXBTdWNjZXNzOiAnYXV0aC1zaWdudXAtc3VjY2VzcycsXG4gICAgICAgIHNpZ251cEZhaWxlZDogJ2F1dGgtc2lnbnVwLWZhaWxlZCcsXG4gICAgICAgIGxvZ291dFN1Y2Nlc3M6ICdhdXRoLWxvZ291dC1zdWNjZXNzJyxcbiAgICAgICAgc2Vzc2lvblRpbWVvdXQ6ICdhdXRoLXNlc3Npb24tdGltZW91dCcsXG4gICAgICAgIG5vdEF1dGhlbnRpY2F0ZWQ6ICdhdXRoLW5vdC1hdXRoZW50aWNhdGVkJyxcbiAgICAgICAgbm90QXV0aG9yaXplZDogJ2F1dGgtbm90LWF1dGhvcml6ZWQnXG4gICAgfSk7XG5cbiAgICBhcHAuZmFjdG9yeSgnQXV0aEludGVyY2VwdG9yJywgZnVuY3Rpb24gKCRyb290U2NvcGUsICRxLCBBVVRIX0VWRU5UUykge1xuICAgICAgICB2YXIgc3RhdHVzRGljdCA9IHtcbiAgICAgICAgICAgIDQwMTogQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCxcbiAgICAgICAgICAgIDQwMzogQVVUSF9FVkVOVFMubm90QXV0aG9yaXplZCxcbiAgICAgICAgICAgIDQxOTogQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsXG4gICAgICAgICAgICA0NDA6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0XG4gICAgICAgIH07XG4gICAgICAgIHJldHVybiB7XG4gICAgICAgICAgICByZXNwb25zZUVycm9yOiBmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3Qoc3RhdHVzRGljdFtyZXNwb25zZS5zdGF0dXNdLCByZXNwb25zZSk7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdChyZXNwb25zZSlcbiAgICAgICAgICAgIH1cbiAgICAgICAgfTtcbiAgICB9KTtcblxuICAgIGFwcC5jb25maWcoZnVuY3Rpb24gKCRodHRwUHJvdmlkZXIpIHtcbiAgICAgICAgJGh0dHBQcm92aWRlci5pbnRlcmNlcHRvcnMucHVzaChbXG4gICAgICAgICAgICAnJGluamVjdG9yJyxcbiAgICAgICAgICAgIGZ1bmN0aW9uICgkaW5qZWN0b3IpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJGluamVjdG9yLmdldCgnQXV0aEludGVyY2VwdG9yJyk7XG4gICAgICAgICAgICB9XG4gICAgICAgIF0pO1xuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ0F1dGhTZXJ2aWNlJywgZnVuY3Rpb24gKCRodHRwLCBTZXNzaW9uLCAkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUywgJHEpIHtcblxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxMb2dpbihyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dpblN1Y2Nlc3MpO1xuICAgICAgICAgICAgcmV0dXJuIGRhdGEudXNlcjtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vYWRkIHN1Y2Nlc3NmdWwgc2lnbnVwXG4gICAgICAgIGZ1bmN0aW9uIG9uU3VjY2Vzc2Z1bFNpZ251cChyZXNwb25zZSkge1xuICAgICAgICAgICAgdmFyIGRhdGEgPSByZXNwb25zZS5kYXRhO1xuICAgICAgICAgICAgU2Vzc2lvbi5jcmVhdGUoZGF0YS5pZCwgZGF0YS51c2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5zaWdudXBTdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBVc2VzIHRoZSBzZXNzaW9uIGZhY3RvcnkgdG8gc2VlIGlmIGFuXG4gICAgICAgIC8vIGF1dGhlbnRpY2F0ZWQgdXNlciBpcyBjdXJyZW50bHkgcmVnaXN0ZXJlZC5cbiAgICAgICAgdGhpcy5pc0F1dGhlbnRpY2F0ZWQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gISFTZXNzaW9uLnVzZXI7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5nZXRMb2dnZWRJblVzZXIgPSBmdW5jdGlvbiAoZnJvbVNlcnZlcikge1xuXG4gICAgICAgICAgICAvLyBJZiBhbiBhdXRoZW50aWNhdGVkIHNlc3Npb24gZXhpc3RzLCB3ZVxuICAgICAgICAgICAgLy8gcmV0dXJuIHRoZSB1c2VyIGF0dGFjaGVkIHRvIHRoYXQgc2Vzc2lvblxuICAgICAgICAgICAgLy8gd2l0aCBhIHByb21pc2UuIFRoaXMgZW5zdXJlcyB0aGF0IHdlIGNhblxuICAgICAgICAgICAgLy8gYWx3YXlzIGludGVyZmFjZSB3aXRoIHRoaXMgbWV0aG9kIGFzeW5jaHJvbm91c2x5LlxuXG4gICAgICAgICAgICAvLyBPcHRpb25hbGx5LCBpZiB0cnVlIGlzIGdpdmVuIGFzIHRoZSBmcm9tU2VydmVyIHBhcmFtZXRlcixcbiAgICAgICAgICAgIC8vIHRoZW4gdGhpcyBjYWNoZWQgdmFsdWUgd2lsbCBub3QgYmUgdXNlZC5cblxuICAgICAgICAgICAgaWYgKHRoaXMuaXNBdXRoZW50aWNhdGVkKCkgJiYgZnJvbVNlcnZlciAhPT0gdHJ1ZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS53aGVuKFNlc3Npb24udXNlcik7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIE1ha2UgcmVxdWVzdCBHRVQgL3Nlc3Npb24uXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgdXNlciwgY2FsbCBvblN1Y2Nlc3NmdWxMb2dpbiB3aXRoIHRoZSByZXNwb25zZS5cbiAgICAgICAgICAgIC8vIElmIGl0IHJldHVybnMgYSA0MDEgcmVzcG9uc2UsIHdlIGNhdGNoIGl0IGFuZCBpbnN0ZWFkIHJlc29sdmUgdG8gbnVsbC5cbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5nZXQoJy9zZXNzaW9uJykudGhlbihvblN1Y2Nlc3NmdWxMb2dpbikuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIHJldHVybiBudWxsO1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmxvZ2luID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL2xvZ2luJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pXG4gICAgICAgICAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuICRxLnJlamVjdCh7IG1lc3NhZ2U6ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLicgfSk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvbG9nb3V0JykudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgU2Vzc2lvbi5kZXN0cm95KCk7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MpO1xuICAgICAgICAgICAgfSk7XG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5zaWdudXAgPSBmdW5jdGlvbiAoY3JlZGVudGlhbHMpIHtcbiAgICAgICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvc2lnbnVwJywgY3JlZGVudGlhbHMpXG4gICAgICAgICAgICAgICAgLnRoZW4ob25TdWNjZXNzZnVsU2lnbnVwKTtcbiAgICAgICAgfTtcblxuXG4gICAgfSk7XG5cbiAgICBhcHAuc2VydmljZSgnU2Vzc2lvbicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCBBVVRIX0VWRU5UUykge1xuXG4gICAgICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5ub3RBdXRoZW50aWNhdGVkLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHNlbGYuZGVzdHJveSgpO1xuICAgICAgICB9KTtcblxuICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcblxuICAgICAgICB0aGlzLmNyZWF0ZSA9IGZ1bmN0aW9uIChzZXNzaW9uSWQsIHVzZXIpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBzZXNzaW9uSWQ7XG4gICAgICAgICAgICB0aGlzLnVzZXIgPSB1c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZGVzdHJveSA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIHRoaXMuaWQgPSBudWxsO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gbnVsbDtcbiAgICAgICAgfTtcblxuICAgIH0pO1xuXG59KSgpO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdob21lJywge1xuICAgICAgICB1cmw6ICcvJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9ob21lL2hvbWUuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uKCRzY29wZSwgRHdlZXRGYWN0b3J5LCBsYXRlc3RUZW1wLCAkcm9vdFNjb3BlLCAkc3RhdGUpIHtcbiAgICAgICAgICAgIC8vQ3JlYXRlIGFycmF5IG9mIGxhdGVzdCBkd2VldHMgdG8gZGlzcGxheSBvbiBob21lIHN0YXRlXG4gICAgICAgICAgICAkc2NvcGUuaG9tZUR3ZWV0cyA9IFtdO1xuICAgICAgICAgICAgJHJvb3RTY29wZS5ob21lQWxlcnRzID0gW107XG5cbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAgICAgICAgIC8vSW5pdGlhbGl6ZSB3aXRoIGZpcnN0IGR3ZWV0XG4gICAgICAgICAgICBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KClcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKGR3ZWV0KXtcbiAgICAgICAgICAgICAgICAkc2NvcGUucHJldkR3ZWV0ID0gZHdlZXQ7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgLy8gYnV0dG9uIGNsaWNrIGxlYWRzIHRvIGFsZXJ0cyBzdGF0ZVxuICAgICAgICAgICAgJHNjb3BlLmdvQWxlcnRzID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICRzdGF0ZS5nbygnYWxlcnRzJyk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgbGluZTEgPSBuZXcgVGltZVNlcmllcygpO1xuICAgICAgICAgICAgdmFyIGxpbmUyID0gbmV3IFRpbWVTZXJpZXMoKTtcblxuICAgICAgICAgICAgLy8gZGVmYXVsdCB0ZW1wZXJhdHVyZSByYW5nZSBpcyA1MC05MCBmb3IgZGVtbyBwdXJwb3Nlc1xuICAgICAgICAgICAgaWYoISRyb290U2NvcGUuYWxlcnQpIHtcbiAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0ID0ge1xuICAgICAgICAgICAgICAgICAgICB1cHBlckJvdW5kOiA5MCxcbiAgICAgICAgICAgICAgICAgICAgbG93ZXJCb3VuZDogNTBcbiAgICAgICAgICAgICAgICB9O1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBDaGVjayBldmVyeSBoYWxmIHNlY29uZCB0byBzZWUgaWYgdGhlIGxhc3QgZHdlZXQgaXMgbmV3LCB0aGVuIHB1c2ggdG8gaG9tZUR3ZWV0cywgdGhlbiBwbG90XG4gICAgICAgICAgICBpZiAoJHJvb3RTY29wZS5hbGVydCkge1xuICAgICAgICAgICAgICAgIHNldEludGVydmFsKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KClcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oZHdlZXQpe1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmxhc3REd2VldCA9IGR3ZWV0O1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByYW5kb21UZW1wID0gTWF0aC5yYW5kb20oKSoyMCs2MDtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgkc2NvcGUucHJldkR3ZWV0LmNyZWF0ZWQgIT0gJHNjb3BlLmxhc3REd2VldC5jcmVhdGVkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMucHVzaCgkc2NvcGUubGFzdER3ZWV0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUucHJldkR3ZWV0ID0gJHNjb3BlLmxhc3REd2VldDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaW5lMS5hcHBlbmQobmV3IERhdGUoKS5nZXRUaW1lKCksICRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1JhbmRvbSBwbG90IHRvIGNoZWNrIHRoYXQgdGhlIGdyYXBoIGlzIHdvcmtpbmdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaW5lMi5hcHBlbmQobmV3IERhdGUoKS5nZXRUaW1lKCksIHJhbmRvbVRlbXApO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgLy9EZXRlY3QgaWYgdGhlIHRlbXBlcmF0dXJlIGJyZWFrcyBvdXQgb2Ygc2FmZSByYW5nZVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddID4gJHJvb3RTY29wZS5hbGVydC51cHBlckJvdW5kIHx8ICRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddIDwgJHJvb3RTY29wZS5hbGVydC5sb3dlckJvdW5kKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ2JyZWFrIGluIGNvbGQgY2hhaW4nKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjdXJyRGF0ZSA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJUaW1lID0gY3VyckRhdGUudG9TdHJpbmcoKS5zbGljZSgxNik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5hbGVydC50aW1lID0gY3VyclRpbWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5hbGVydC50ZW1wID0gJHNjb3BlLmxhc3REd2VldC5jb250ZW50WydhaU91dHNpZGVUZW1wX2RlZ3JlZXNGJ107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgRHdlZXRGYWN0b3J5LnBvc3RBbGVydCgkcm9vdFNjb3BlLmFsZXJ0KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuIChmdW5jdGlvbiAocG9zdGVkQWxlcnQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5ob21lQWxlcnRzLnB1c2gocG9zdGVkQWxlcnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnQnJlYWsgaW4gY29sZCBjaGFpbiBkZXRlY3RlZCEhJ1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAvL0RldGVjdCBpZiB0aGUgdGVtcGVyYXR1cmUgYnJlYWtzIG91dCBvZiBzYWZlIHJhbmdlXG4gICAgICAgICAgICAvL1RVUk4gT04gVE8gREVNT05TVFJBVEUgQlJFQUsgSU4gQ09MRCBDSEFJTiBBTEVSVCAmIEVNQUlMIEZFQVRVUkVcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyYW5kb21UZW1wID4gJHJvb3RTY29wZS5hbGVydC51cHBlckJvdW5kIHx8IHJhbmRvbVRlbXAgPCAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnYnJlYWsgaW4gY29sZCBjaGFpbiAyJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY3VyclRpbWUgPSBjdXJyRGF0ZS50b1N0cmluZygpLnNsaWNlKDE2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRpbWUgPSBjdXJyVGltZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRlbXAgPSByYW5kb21UZW1wO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIER3ZWV0RmFjdG9yeS5wb3N0QWxlcnQoJHJvb3RTY29wZS5hbGVydClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAudGhlbiAoZnVuY3Rpb24gKHBvc3RlZEFsZXJ0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRyb290U2NvcGUuaG9tZUFsZXJ0cy5wdXNoKHBvc3RlZEFsZXJ0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0JyZWFrIGluIGNvbGQgY2hhaW4gZGV0ZWN0ZWQhISdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICB3aGlsZSgkc2NvcGUuaG9tZUR3ZWV0cy5sZW5ndGggPiAxMDApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuaG9tZUR3ZWV0cy5zaGlmdCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUoJHNjb3BlLmhvbWVBbGVydHMubGVuZ3RoID4gMTAwKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmhvbWVBbGVydHMuc2hpZnQoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvL01ha2UgYSBzbW9vdGhpZSBjaGFydCB3aXRoIGFlc3RoZXRpY2FsbHkgcGxlYXNpbmcgcHJvcGVydGllc1xuICAgICAgICAgICAgdmFyIHNtb290aGllID0gbmV3IFNtb290aGllQ2hhcnQoe1xuICAgICAgICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoNjMsIDE2MCwgMTgyKScsXG4gICAgICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYig0LCA1LCA5MSknLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6IDEsXG4gICAgICAgICAgICAgICAgICAgIG1pbGxpc1BlckxpbmU6IDUwMCxcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWxTZWN0aW9uczogNFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgbWF4VmFsdWU6ICRyb290U2NvcGUuYWxlcnQudXBwZXJCb3VuZCAqIDEuMDAzLFxuICAgICAgICAgICAgICAgIG1pblZhbHVlOiAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQgKiAwLjk5NyxcbiAgICAgICAgICAgICAgICAvLyBtYXhWYWx1ZVNjYWxlOiAxLjAxLFxuICAgICAgICAgICAgICAgIC8vIG1pblZhbHVlU2NhbGU6IDEuMDIsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wRm9ybWF0dGVyOlNtb290aGllQ2hhcnQudGltZUZvcm1hdHRlcixcbiAgICAgICAgICAgICAgICAvL1RoZSByYW5nZSBvZiBhY2NlcHRhYmxlIHRlbXBlcmF0dXJlcyB2aXN1YWxpemVkXG4gICAgICAgICAgICAgICAgLy9TaG91bGQgY2hhbmdlICd2YWx1ZScgYWNjb3JkaW5nbHlcbiAgICAgICAgICAgICAgICBob3Jpem9udGFsTGluZXM6W3tcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6JyM4ODAwMDAnLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6NSxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6ICgkcm9vdFNjb3BlLmFsZXJ0LnVwcGVyQm91bmQgfHwgNzApXG4gICAgICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgICAgICBjb2xvcjonIzg4MDAwMCcsXG4gICAgICAgICAgICAgICAgICAgIGxpbmVXaWR0aDo1LFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZTogKCRyb290U2NvcGUuYWxlcnQubG93ZXJCb3VuZCB8fCA2OClcbiAgICAgICAgICAgICAgICB9XVxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTEsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigwLCAyNTUsIDApJyxcbiAgICAgICAgICAgICAgICBmaWxsU3R5bGU6ICdyZ2JhKDAsIDI1NSwgMCwgMC40KScsXG4gICAgICAgICAgICAgICAgbGluZVdpZHRoOiAzXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTIsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigyNTUsIDAsIDI1NSknLFxuICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYmEoMjU1LCAwLCAyNTUsIDAuMyknLFxuICAgICAgICAgICAgICAgIGxpbmVXaWR0aDogM1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLnN0cmVhbVRvKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiY2hhcnRcIiksIDMwMCk7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGxhdGVzdFRlbXA6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpXG4gICAgICAgICAgICAgICAgLnRoZW4oIGZ1bmN0aW9uIChkd2VldCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbGF0ZXN0Jywge1xuICAgICAgICB1cmw6ICcvZGF0YS9sYXRlc3QnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xhdGVzdC9sYXRlc3QuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIGxhdGVzdER3ZWV0KSB7XG4gICAgICAgICAgJHNjb3BlLmxhdGVzdER3ZWV0ID0gbGF0ZXN0RHdlZXQ7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGxhdGVzdER3ZWV0OiBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIER3ZWV0RmFjdG9yeS5nZXRMYXRlc3QoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pXG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xvZ2luJywge1xuICAgIHVybDogJy9sb2dpbicsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9sb2dpbi9sb2dpbi5odG1sJyxcbiAgICBjb250cm9sbGVyOiAnTG9naW5DdHJsJ1xuICB9KTtcbn0pO1xuXG5hcHAuY29udHJvbGxlcignTG9naW5DdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICRzY29wZS5sb2dpbiA9IHt9O1xuICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICRzY29wZS5zZW5kTG9naW4gPSBmdW5jdGlvbiAobG9naW5JbmZvKSB7XG5cbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgQXV0aFNlcnZpY2UubG9naW4obG9naW5JbmZvKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgIGlmKHVzZXIubmV3UGFzcykgJHN0YXRlLmdvKCdyZXNldFBhc3MnLCB7J3VzZXJJZCc6IHVzZXIuX2lkfSk7XG4gICAgICBlbHNlICRzdGF0ZS5nbygnaG9tZScpO1xuICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5lcnJvciA9ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLic7XG4gICAgfSk7XG4gIH07XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAuc3RhdGUoJ3Jlc2V0UGFzcycsIHtcbiAgICAgICAgdXJsOiAnL3Jlc2V0Lzp1c2VySWQnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3Jlc2V0UGFzcy9yZXNldFBhc3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdSZXNldEN0cmwnXG4gICAgfSk7XG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1Jlc2V0Q3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIFVzZXJGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5yZXNldFBhc3MgPSBmdW5jdGlvbiAobmV3UGFzcykge1xuICAgICAgICBVc2VyRmFjdG9yeS5lZGl0KCRzdGF0ZVBhcmFtcy51c2VySWQsIHsnbmV3UGFzcyc6IGZhbHNlLCAncGFzc3dvcmQnOiBuZXdQYXNzfSlcbiAgICAgICAgLnRoZW4oIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICBBdXRoU2VydmljZS5sb2dpbih7ZW1haWw6IHVzZXIuZW1haWwsIHBhc3N3b3JkOiBuZXdQYXNzfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSlcbiAgICB9XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdzaWdudXAnLCB7XG4gICAgICAgIHVybDogJy9zaWdudXAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3NpZ251cC9zaWdudXAuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaWdudXBDdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1NpZ251cEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgJHNjb3BlLnNlbmRTaWdudXA9IGZ1bmN0aW9uIChzaWdudXBJbmZvKSB7XG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG4gICAgICAgIEF1dGhTZXJ2aWNlLnNpZ251cChzaWdudXBJbmZvKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdFbWFpbCBpcyB0YWtlbiEnO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcil7XG4gICRzdGF0ZVByb3ZpZGVyXG4gIC5zdGF0ZSgndXNlcicsIHtcbiAgICB1cmw6ICcvdXNlci86dXNlcklkJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy91c2VyL3VzZXIuaHRtbCcsXG4gICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgZmluZFVzZXIpIHtcbiAgICAgICRzY29wZS51c2VyID0gZmluZFVzZXI7XG4gICAgfSxcbiAgICByZXNvbHZlOiB7XG4gICAgICBmaW5kVXNlcjogZnVuY3Rpb24gKCRzdGF0ZVBhcmFtcywgVXNlckZhY3RvcnkpIHtcbiAgICAgICAgcmV0dXJuIFVzZXJGYWN0b3J5LmdldEJ5SWQoJHN0YXRlUGFyYW1zLnVzZXJJZClcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24odXNlcil7XG4gICAgICAgICAgcmV0dXJuIHVzZXI7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICB9XG4gIH0pO1xufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKXtcblx0JHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3VzZXJzJywge1xuXHRcdHVybDogJy91c2VycycsXG5cdFx0dGVtcGxhdGVVcmw6ICcvanMvdXNlcnMvdXNlcnMuaHRtbCcsXG5cdFx0cmVzb2x2ZTp7XG5cdFx0XHR1c2VyczogZnVuY3Rpb24oVXNlckZhY3Rvcnkpe1xuXHRcdFx0XHRyZXR1cm4gVXNlckZhY3RvcnkuZ2V0QWxsKCk7XG5cdFx0XHR9XG5cdFx0fSxcblx0XHRjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCB1c2VycywgU2Vzc2lvbiwgJHN0YXRlKSB7XG5cdFx0XHQkc2NvcGUudXNlcnMgPSB1c2VycztcblxuICAgICAgICAgICAgLy9XSFkgTk9UIE9OIFNFU1NJT04/Pz8/XG5cdFx0XHQvLyBpZiAoIVNlc3Npb24udXNlciB8fCAhU2Vzc2lvbi51c2VyLmlzQWRtaW4pe1xuXHRcdFx0Ly8gXHQkc3RhdGUuZ28oJ2hvbWUnKTtcblx0XHRcdC8vIH1cblx0XHR9XG59KTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0R3ZWV0RmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuICAgIHZhciBEd2VldHMgPSBmdW5jdGlvbihwcm9wcykge1xuICAgICAgICBhbmd1bGFyLmV4dGVuZCh0aGlzLCBwcm9wcyk7XG4gICAgfTtcblxuICAgIER3ZWV0cy5nZXRBbGwgPSBmdW5jdGlvbiAoKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9kYXRhJylcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKXtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KVxuXHR9O1xuXG4gICAgRHdlZXRzLmdldExhdGVzdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9kYXRhL2xhdGVzdCcpXG4gICAgICAgIC50aGVuIChmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KVxuICAgIH07XG5cbiAgICBEd2VldHMucG9zdEFsZXJ0ID0gZnVuY3Rpb24gKGFsZXJ0KSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2FsZXJ0cycsIGFsZXJ0KVxuICAgICAgICAudGhlbiAoIGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pO1xuICAgIH07XG5cbiAgICByZXR1cm4gRHdlZXRzO1xufSlcbiIsImFwcC5mYWN0b3J5KCdVc2VyRmFjdG9yeScsIGZ1bmN0aW9uKCRodHRwKXtcblxuXHR2YXIgVXNlciA9IGZ1bmN0aW9uKHByb3BzKXtcblx0XHRhbmd1bGFyLmV4dGVuZCh0aGlzLCBwcm9wcyk7XG5cdH07XG5cblx0VXNlci5nZXRBbGwgPSBmdW5jdGlvbiAoKXtcblx0XHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL3VzZXJzJylcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXHRVc2VyLmdldEJ5SWQgPSBmdW5jdGlvbiAoaWQpIHtcblx0XHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL3VzZXJzLycgKyBpZClcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXHRVc2VyLmVkaXQgPSBmdW5jdGlvbiAoaWQsIHByb3BzKSB7XG5cdFx0cmV0dXJuICRodHRwLnB1dCgnL2FwaS91c2Vycy8nICsgaWQsIHByb3BzKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cdFVzZXIuZGVsZXRlID0gZnVuY3Rpb24gKGlkKSB7XG5cdFx0cmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS91c2Vycy8nICsgaWQpXG5cdFx0LnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXG5cdHJldHVybiBVc2VyO1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCdkd2VldExpc3QnLCBmdW5jdGlvbigpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvY29tbW9uL2RpcmVjdGl2ZXMvZHdlZXQvZHdlZXQtbGlzdC5odG1sJ1xuICB9O1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKFwiZWRpdEJ1dHRvblwiLCBmdW5jdGlvbiAoKSB7XG5cdHJldHVybiB7XG5cdFx0cmVzdHJpY3Q6ICdFQScsXG5cdFx0dGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9lZGl0LWJ1dHRvbi9lZGl0LWJ1dHRvbi5odG1sJyxcblx0fTtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZShcImVkaXRQYXNzQnV0dG9uXCIsIGZ1bmN0aW9uICgpIHtcblx0cmV0dXJuIHtcblx0XHRyZXN0cmljdDogJ0VBJyxcblx0XHR0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2VkaXQtcGFzcy1idXR0b24vZWRpdC1wYXNzLWJ1dHRvbi5odG1sJyxcblx0fTtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgnbmF2YmFyJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCBBVVRIX0VWRU5UUywgJHN0YXRlKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICBzY29wZToge30sXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG5cbiAgICAgICAgICAgIHNjb3BlLml0ZW1zID0gW1xuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdBbGVydHMnLCBzdGF0ZTogJ2FsZXJ0cycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRGF0YScsIHN0YXRlOiAnZGF0YScgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnTGF0ZXN0Jywgc3RhdGU6ICdsYXRlc3QnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ1VzZXJzJywgc3RhdGU6ICd1c2VycycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfVxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgc2V0VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSB1c2VyO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHJlbW92ZVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzZXRVc2VyKCk7XG5cbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zaWdudXBTdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MsIHJlbW92ZVVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIHJlbW92ZVVzZXIpO1xuXG4gICAgICAgIH1cblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgndXNlckRldGFpbCcsIGZ1bmN0aW9uKFVzZXJGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICRzdGF0ZSwgU2Vzc2lvbil7XG4gIHJldHVybiB7XG5cdHJlc3RyaWN0OiAnRScsXG5cdHRlbXBsYXRlVXJsOiAnL2pzL2NvbW1vbi9kaXJlY3RpdmVzL3VzZXIvdXNlci1kZXRhaWwvdXNlci1kZXRhaWwuaHRtbCcsXG5cdGxpbms6IGZ1bmN0aW9uIChzY29wZSl7XG5cdFx0c2NvcGUuaXNEZXRhaWwgPSB0cnVlO1xuXHRcdHNjb3BlLmlzQWRtaW4gPSBTZXNzaW9uLnVzZXIuaXNBZG1pbjtcblx0XHRzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuICAgICAgICBzY29wZS5lZGl0UGFzcyA9IGZhbHNlO1xuXG4gICAgICAgIC8vRklYIFRISVMgTElORVxuICAgICAgICBpZiAoc2NvcGUudXNlciA9IFNlc3Npb24udXNlcikgc2NvcGUuaXNPd25lciA9IHRydWVcblxuXHRcdHNjb3BlLmVuYWJsZUVkaXQgPSBmdW5jdGlvbiAoKSB7XG5cdFx0XHRzY29wZS5jYWNoZWQgPSBhbmd1bGFyLmNvcHkoc2NvcGUudXNlcik7XG5cdFx0XHRzY29wZS5lZGl0TW9kZSA9IHRydWU7XG5cdFx0fTtcblx0XHRzY29wZS5jYW5jZWxFZGl0ID0gZnVuY3Rpb24oKXtcblx0XHRcdHNjb3BlLnVzZXIgPSBhbmd1bGFyLmNvcHkoc2NvcGUuY2FjaGVkKTtcblx0XHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgICAgICBzY29wZS5lZGl0UGFzcz0gZmFsc2U7XG5cdFx0fTtcblx0XHRzY29wZS5zYXZlVXNlciA9IGZ1bmN0aW9uICh1c2VyKSB7XG5cdFx0XHRVc2VyRmFjdG9yeS5lZGl0KHVzZXIuX2lkLCB1c2VyKVxuXHRcdFx0LnRoZW4oZnVuY3Rpb24gKHVwZGF0ZWRVc2VyKSB7XG5cdFx0XHRcdHNjb3BlLnVzZXIgPSB1cGRhdGVkVXNlcjtcblx0XHRcdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICBzY29wZS5lZGl0UGFzcz0gZmFsc2U7XG5cdFx0XHR9KTtcblx0XHR9O1xuXHRcdHNjb3BlLmRlbGV0ZVVzZXIgPSBmdW5jdGlvbih1c2VyKXtcblx0XHRcdFVzZXJGYWN0b3J5LmRlbGV0ZSh1c2VyKVxuXHRcdFx0LnRoZW4oZnVuY3Rpb24oKXtcblx0XHRcdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICBzY29wZS5lZGl0UGFzcz0gZmFsc2U7XG5cdFx0XHRcdCRzdGF0ZS5nbygnaG9tZScpO1xuXHRcdFx0fSk7XG5cdFx0fTtcblxuICAgICAgICBzY29wZS5wYXNzd29yZEVkaXQgPSBmdW5jdGlvbigpe1xuICAgICAgICAgICAgLy8gVXNlckZhY3RvcnkuZWRpdChpZCwgeyduZXdQYXNzJzogdHJ1ZX0pXG4gICAgICAgICAgICAvLyAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAvLyAgICAgLy8gc2NvcGUubmV3UGFzcyA9IHRydWU7XG4gICAgICAgICAgICAvLyAgICAgc2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgIC8vIH0pO1xuICAgICAgICAgICAgc2NvcGUuY2FjaGVkID0gYW5ndWxhci5jb3B5KHNjb3BlLnVzZXIpO1xuICAgICAgICAgICAgc2NvcGUuZWRpdFBhc3MgPSB0cnVlO1xuICAgICAgICB9O1xuXHR9LFxuXHRzY29wZToge1xuXHRcdHVzZXI6IFwiPVwiXG5cdH1cbiAgfTtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgndXNlckxpc3QnLCBmdW5jdGlvbigpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWxpc3QvdXNlci1saXN0Lmh0bWwnXG4gIH07XG59KTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
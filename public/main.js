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
                $rootScope.alert = {};
                $rootScope.alert.lowerBound = 50;
                $rootScope.alert.upperBound = 90;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFsZXJ0cy9hbGVydHMuanMiLCJkYXRhL2RhdGEuanMiLCJkb2NzL2RvY3MuanMiLCJmc2EvZnNhLXByZS1idWlsdC5qcyIsImhvbWUvaG9tZS5qcyIsImxhdGVzdC9sYXRlc3QuanMiLCJsb2dpbi9sb2dpbi5qcyIsInJlc2V0UGFzcy9yZXNldFBhc3MuanMiLCJzaWdudXAvc2lnbnVwLmpzIiwidXNlci91c2VyLmpzIiwidXNlcnMvdXNlcnMuanMiLCJjb21tb24vZmFjdG9yaWVzL2R3ZWV0LWZhY3RvcnkuanMiLCJjb21tb24vZmFjdG9yaWVzL3VzZXItZmFjdG9yeS5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2R3ZWV0L2R3ZWV0LWxpc3QuanMiLCJjb21tb24vZGlyZWN0aXZlcy9lZGl0LWJ1dHRvbi9lZGl0LWJ1dHRvbi5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2VkaXQtcGFzcy1idXR0b24vZWRpdC1wYXNzLWJ1dHRvbi5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItZGV0YWlsL3VzZXItZGV0YWlsLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWxpc3QvdXNlci1saXN0LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLFlBQUEsQ0FBQTtBQUNBLE1BQUEsQ0FBQSxHQUFBLEdBQUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxTQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLGFBQUEsQ0FBQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7O0FBR0Esc0JBQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBOztBQUVBLFlBQUEsRUFBQSxHQUFBLG1CQUFBLENBQUE7QUFDQSxZQUFBLElBQUEsR0FBQSxTQUFBLENBQUEsR0FBQSxFQUFBLENBQUE7O0FBRUEsWUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLE9BQUEsQ0FBQSxFQUFBLEVBQUEsTUFBQSxDQUFBLENBQUE7U0FDQTs7QUFFQSxlQUFBLEtBQUEsQ0FBQTtLQUNBLENBQUEsQ0FBQTs7QUFFQSxxQkFBQSxDQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsWUFBQTtBQUNBLGNBQUEsQ0FBQSxRQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsc0JBQUEsQ0FBQSxTQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7OztBQUdBLEdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7O0FBR0EsUUFBQSw0QkFBQSxHQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxJQUFBLElBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxZQUFBLENBQUE7S0FDQSxDQUFBOzs7O0FBSUEsY0FBQSxDQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDRCQUFBLENBQUEsT0FBQSxDQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7O0FBRUEsWUFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7OztBQUdBLGFBQUEsQ0FBQSxjQUFBLEVBQUEsQ0FBQTs7QUFFQSxtQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTs7OztBQUlBLGdCQUFBLElBQUEsRUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxNQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsT0FBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUEsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUNuRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxTQUFBO0FBQ0EsbUJBQUEsRUFBQSx1QkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBLFVBQUEsRUFBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0EsYUFBQSxDQUFBLFVBQUEsR0FBQSxNQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxDQUFBLFVBQUEsR0FBQSxNQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsQ0FBQSxDQUFBO0FBQ0EsYUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLGtCQUFBLENBQUEsWUFBQSxHQUFBLElBQUEsQ0FBQTtBQUNBLGNBQUEsQ0FBQSxFQUFBLENBQUEsTUFBQSxDQUFBLENBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ2xCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLE9BQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxNQUFBLEdBQUEsU0FBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7Ozs7QUFJQSxxQkFBQSxFQUFBLG1CQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLFlBQUEsQ0FBQSxNQUFBLEVBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDakJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsT0FBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsQ0FBQSxZQUFBOztBQUVBLGdCQUFBLENBQUE7OztBQUdBLFFBQUEsQ0FBQSxNQUFBLENBQUEsT0FBQSxFQUFBLE1BQUEsSUFBQSxLQUFBLENBQUEsd0JBQUEsQ0FBQSxDQUFBOztBQUVBLFFBQUEsR0FBQSxHQUFBLE9BQUEsQ0FBQSxNQUFBLENBQUEsYUFBQSxFQUFBLEVBQUEsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxPQUFBLENBQUEsUUFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLENBQUEsTUFBQSxDQUFBLEVBQUEsRUFBQSxNQUFBLElBQUEsS0FBQSxDQUFBLHNCQUFBLENBQUEsQ0FBQTtBQUNBLGVBQUEsTUFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQSxDQUFBOzs7OztBQUtBLE9BQUEsQ0FBQSxRQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7QUFDQSxxQkFBQSxFQUFBLHFCQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7QUFDQSxzQkFBQSxFQUFBLHNCQUFBO0FBQ0Esd0JBQUEsRUFBQSx3QkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsVUFBQSxFQUFBLEVBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsRUFBQSxXQUFBLENBQUEsZ0JBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGFBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7U0FDQSxDQUFBO0FBQ0EsZUFBQTtBQUNBLHlCQUFBLEVBQUEsdUJBQUEsUUFBQSxFQUFBO0FBQ0EsMEJBQUEsQ0FBQSxVQUFBLENBQUEsVUFBQSxDQUFBLFFBQUEsQ0FBQSxNQUFBLENBQUEsRUFBQSxRQUFBLENBQUEsQ0FBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLHFCQUFBLENBQUEsWUFBQSxDQUFBLElBQUEsQ0FBQSxDQUNBLFdBQUEsRUFDQSxVQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsQ0FBQSxHQUFBLENBQUEsaUJBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsRUFBQSxFQUFBOztBQUVBLGlCQUFBLGlCQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsRUFBQSxFQUFBLElBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQTs7O0FBR0EsaUJBQUEsa0JBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLEdBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBLEVBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBOzs7O0FBSUEsWUFBQSxDQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsQ0FBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxlQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7Ozs7Ozs7Ozs7QUFVQSxnQkFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLElBQUEsVUFBQSxLQUFBLElBQUEsRUFBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO2FBQ0E7Ozs7O0FBS0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsaUJBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUVBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsUUFBQSxFQUFBLFdBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxpQkFBQSxDQUFBLFNBQ0EsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxFQUFBLE9BQUEsRUFBQSw0QkFBQSxFQUFBLENBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7QUFDQSwwQkFBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsa0JBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQTtLQUdBLENBQUEsQ0FBQTs7QUFFQSxPQUFBLENBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxJQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxnQkFBQSxFQUFBLFlBQUE7QUFDQSxnQkFBQSxDQUFBLE9BQUEsRUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxjQUFBLEVBQUEsWUFBQTtBQUNBLGdCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEVBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxZQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxZQUFBLENBQUEsTUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLENBQUEsRUFBQSxHQUFBLFNBQUEsQ0FBQTtBQUNBLGdCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxFQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsRUFBQSxDQUFBOztBQ3BKQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsWUFBQSxFQUFBLFVBQUEsRUFBQSxVQUFBLEVBQUEsTUFBQSxFQUFBOztBQUVBLGtCQUFBLENBQUEsVUFBQSxHQUFBLEVBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxHQUFBLEVBQUEsQ0FBQTs7QUFFQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7OztBQUdBLHdCQUFBLENBQUEsU0FBQSxFQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsS0FBQSxFQUFBO0FBQ0Esc0JBQUEsQ0FBQSxTQUFBLEdBQUEsS0FBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOzs7QUFHQSxrQkFBQSxDQUFBLFFBQUEsR0FBQSxZQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBOztBQUVBLGdCQUFBLEtBQUEsR0FBQSxJQUFBLFVBQUEsRUFBQSxDQUFBO0FBQ0EsZ0JBQUEsS0FBQSxHQUFBLElBQUEsVUFBQSxFQUFBLENBQUE7OztBQUdBLGdCQUFBLENBQUEsVUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDBCQUFBLENBQUEsS0FBQSxHQUFBLEVBQUEsQ0FBQTtBQUNBLDBCQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsR0FBQSxFQUFBLENBQUE7QUFDQSwwQkFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEdBQUEsRUFBQSxDQUFBO2FBQ0E7OztBQUdBLGdCQUFBLFVBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSwyQkFBQSxDQUFBLFlBQUE7QUFDQSxnQ0FBQSxDQUFBLFNBQUEsRUFBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLDhCQUFBLENBQUEsU0FBQSxHQUFBLEtBQUEsQ0FBQTtxQkFDQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7QUFDQSw0QkFBQSxVQUFBLEdBQUEsSUFBQSxDQUFBLE1BQUEsRUFBQSxHQUFBLEVBQUEsR0FBQSxFQUFBLENBQUE7QUFDQSw0QkFBQSxNQUFBLENBQUEsU0FBQSxDQUFBLE9BQUEsSUFBQSxNQUFBLENBQUEsU0FBQSxDQUFBLE9BQUEsRUFBQTtBQUNBLGtDQUFBLENBQUEsVUFBQSxDQUFBLElBQUEsQ0FBQSxNQUFBLENBQUEsU0FBQSxDQUFBLENBQUE7QUFDQSxrQ0FBQSxDQUFBLFNBQUEsR0FBQSxNQUFBLENBQUEsU0FBQSxDQUFBO0FBQ0EsaUNBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxJQUFBLEVBQUEsQ0FBQSxPQUFBLEVBQUEsRUFBQSxNQUFBLENBQUEsU0FBQSxDQUFBLE9BQUEsQ0FBQSx3QkFBQSxDQUFBLENBQUEsQ0FBQTs7QUFFQSxpQ0FBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLElBQUEsRUFBQSxDQUFBLE9BQUEsRUFBQSxFQUFBLFVBQUEsQ0FBQSxDQUFBO3lCQUNBOztBQUVBLDRCQUFBLE1BQUEsQ0FBQSxTQUFBLENBQUEsT0FBQSxDQUFBLHdCQUFBLENBQUEsR0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsSUFBQSxNQUFBLENBQUEsU0FBQSxDQUFBLE9BQUEsQ0FBQSx3QkFBQSxDQUFBLEdBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEVBQUE7QUFDQSxtQ0FBQSxDQUFBLEdBQUEsQ0FBQSxxQkFBQSxDQUFBLENBQUE7QUFDQSxnQ0FBQSxRQUFBLEdBQUEsSUFBQSxJQUFBLEVBQUEsQ0FBQTtBQUNBLGdDQUFBLFFBQUEsR0FBQSxRQUFBLENBQUEsUUFBQSxFQUFBLENBQUEsS0FBQSxDQUFBLEVBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQTtBQUNBLHNDQUFBLENBQUEsS0FBQSxDQUFBLElBQUEsR0FBQSxNQUFBLENBQUEsU0FBQSxDQUFBLE9BQUEsQ0FBQSx3QkFBQSxDQUFBLENBQUE7QUFDQSx3Q0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsMENBQUEsQ0FBQSxVQUFBLENBQUEsSUFBQSxDQUFBLFdBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLEdBQUEsZ0NBQUEsQ0FBQTs2QkFDQSxDQUFBLENBQUE7eUJBQ0E7OztBQUdBLDRCQUFBLFVBQUEsR0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsSUFBQSxVQUFBLEdBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEVBQUE7QUFDQSxtQ0FBQSxDQUFBLEdBQUEsQ0FBQSx1QkFBQSxDQUFBLENBQUE7QUFDQSxnQ0FBQSxRQUFBLEdBQUEsSUFBQSxJQUFBLEVBQUEsQ0FBQTtBQUNBLGdDQUFBLFFBQUEsR0FBQSxRQUFBLENBQUEsUUFBQSxFQUFBLENBQUEsS0FBQSxDQUFBLEVBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQTtBQUNBLHNDQUFBLENBQUEsS0FBQSxDQUFBLElBQUEsR0FBQSxVQUFBLENBQUE7QUFDQSx3Q0FBQSxDQUFBLFNBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EsMENBQUEsQ0FBQSxVQUFBLENBQUEsSUFBQSxDQUFBLFdBQUEsQ0FBQSxDQUFBO0FBQ0Esc0NBQUEsQ0FBQSxLQUFBLEdBQUEsZ0NBQUEsQ0FBQTs2QkFDQSxDQUFBLENBQUE7eUJBQ0E7O0FBRUEsK0JBQUEsTUFBQSxDQUFBLFVBQUEsQ0FBQSxNQUFBLEdBQUEsR0FBQSxFQUFBO0FBQ0Esa0NBQUEsQ0FBQSxVQUFBLENBQUEsS0FBQSxFQUFBLENBQUE7eUJBQ0E7QUFDQSwrQkFBQSxNQUFBLENBQUEsVUFBQSxDQUFBLE1BQUEsR0FBQSxHQUFBLEVBQUE7QUFDQSxrQ0FBQSxDQUFBLFVBQUEsQ0FBQSxLQUFBLEVBQUEsQ0FBQTt5QkFDQTtxQkFDQSxDQUFBLENBQUE7aUJBQ0EsRUFBQSxHQUFBLENBQUEsQ0FBQTthQUNBOzs7QUFHQSxnQkFBQSxRQUFBLEdBQUEsSUFBQSxhQUFBLENBQUE7QUFDQSxvQkFBQSxFQUFBO0FBQ0EsK0JBQUEsRUFBQSxtQkFBQTtBQUNBLDZCQUFBLEVBQUEsZUFBQTtBQUNBLDZCQUFBLEVBQUEsQ0FBQTtBQUNBLGlDQUFBLEVBQUEsR0FBQTtBQUNBLG9DQUFBLEVBQUEsQ0FBQTtpQkFDQTtBQUNBLHdCQUFBLEVBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEdBQUEsS0FBQTtBQUNBLHdCQUFBLEVBQUEsVUFBQSxDQUFBLEtBQUEsQ0FBQSxVQUFBLEdBQUEsS0FBQTs7O0FBR0Esa0NBQUEsRUFBQSxhQUFBLENBQUEsYUFBQTs7O0FBR0EsK0JBQUEsRUFBQSxDQUFBO0FBQ0EseUJBQUEsRUFBQSxTQUFBO0FBQ0EsNkJBQUEsRUFBQSxDQUFBO0FBQ0EseUJBQUEsRUFBQSxVQUFBLENBQUEsS0FBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO2lCQUNBLEVBQUE7QUFDQSx5QkFBQSxFQUFBLFNBQUE7QUFDQSw2QkFBQSxFQUFBLENBQUE7QUFDQSx5QkFBQSxFQUFBLFVBQUEsQ0FBQSxLQUFBLENBQUEsVUFBQSxJQUFBLEVBQUE7aUJBQ0EsQ0FBQTthQUNBLENBQUEsQ0FBQTs7QUFFQSxvQkFBQSxDQUFBLGFBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSwyQkFBQSxFQUFBLGdCQUFBO0FBQ0EseUJBQUEsRUFBQSxzQkFBQTtBQUNBLHlCQUFBLEVBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtBQUNBLG9CQUFBLENBQUEsYUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLEVBQUEsa0JBQUE7QUFDQSx5QkFBQSxFQUFBLHdCQUFBO0FBQ0EseUJBQUEsRUFBQSxDQUFBO2FBQ0EsQ0FBQSxDQUFBOztBQUVBLG9CQUFBLENBQUEsUUFBQSxDQUFBLFFBQUEsQ0FBQSxjQUFBLENBQUEsT0FBQSxDQUFBLEVBQUEsR0FBQSxDQUFBLENBQUE7U0FDQTtBQUNBLGVBQUEsRUFBQTtBQUNBLHNCQUFBLEVBQUEsb0JBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsWUFBQSxDQUFBLFNBQUEsRUFBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLDJCQUFBLEtBQUEsQ0FBQSxPQUFBLENBQUEsd0JBQUEsQ0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDdklBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsY0FBQTtBQUNBLG1CQUFBLEVBQUEsdUJBQUE7QUFDQSxrQkFBQSxFQUFBLG9CQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLFdBQUEsR0FBQSxXQUFBLENBQUE7U0FDQTtBQUNBLGVBQUEsRUFBQTtBQUNBLHVCQUFBLEVBQUEscUJBQUEsWUFBQSxFQUFBO0FBQ0EsdUJBQUEsWUFBQSxDQUFBLFNBQUEsRUFBQSxDQUFBO2FBQ0E7U0FDQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNiQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsT0FBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLFFBQUE7QUFDQSxtQkFBQSxFQUFBLHFCQUFBO0FBQ0Esa0JBQUEsRUFBQSxXQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQUVBLEdBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsVUFBQSxDQUFBLEtBQUEsR0FBQSxFQUFBLENBQUE7QUFDQSxVQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsU0FBQSxFQUFBOztBQUVBLGNBQUEsQ0FBQSxLQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLG1CQUFBLENBQUEsS0FBQSxDQUFBLFNBQUEsQ0FBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsQ0FBQSxPQUFBLEVBQUEsTUFBQSxDQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsRUFBQSxRQUFBLEVBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxDQUFBLENBQUEsS0FDQSxNQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxTQUFBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLDRCQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ3hCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsV0FBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLGdCQUFBO0FBQ0EsbUJBQUEsRUFBQSw2QkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLENBQUEsSUFBQSxDQUFBLFlBQUEsQ0FBQSxNQUFBLEVBQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFBQSxPQUFBLEVBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLHVCQUFBLENBQUEsS0FBQSxDQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsQ0FBQSxLQUFBLEVBQUEsUUFBQSxFQUFBLE9BQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7QUFDQSxzQkFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDcEJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7O0FBRUEsa0JBQUEsQ0FBQSxLQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLFNBQUE7QUFDQSxtQkFBQSxFQUFBLHVCQUFBO0FBQ0Esa0JBQUEsRUFBQSxZQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQUVBLEdBQUEsQ0FBQSxVQUFBLENBQUEsWUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsVUFBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFVBQUEsR0FBQSxVQUFBLFVBQUEsRUFBQTtBQUNBLGNBQUEsQ0FBQSxLQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsbUJBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7QUFDQSxrQkFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTtTQUNBLENBQUEsU0FDQSxDQUFBLFlBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxpQkFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBRUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUMxQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQ0EsS0FBQSxDQUFBLE1BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxlQUFBO0FBQ0EsbUJBQUEsRUFBQSxvQkFBQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLFFBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQTtTQUNBO0FBQ0EsZUFBQSxFQUFBO0FBQ0Esb0JBQUEsRUFBQSxrQkFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxDQUFBLE9BQUEsQ0FBQSxZQUFBLENBQUEsTUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMkJBQUEsSUFBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDakJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsUUFBQTtBQUNBLG1CQUFBLEVBQUEsc0JBQUE7QUFDQSxlQUFBLEVBQUE7QUFDQSxpQkFBQSxFQUFBLGVBQUEsV0FBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxDQUFBLE1BQUEsRUFBQSxDQUFBO2FBQ0E7U0FDQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLEdBQUEsS0FBQSxDQUFBOzs7Ozs7U0FNQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNsQkEsR0FBQSxDQUFBLE9BQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxRQUFBLE1BQUEsR0FBQSxTQUFBLE1BQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsRUFBQSxLQUFBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFVBQUEsQ0FBQSxTQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxrQkFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxhQUFBLEVBQUEsS0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsV0FBQSxNQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDM0JBLEdBQUEsQ0FBQSxPQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBOztBQUVBLFFBQUEsSUFBQSxHQUFBLFNBQUEsSUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsWUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsUUFBQSxDQUFBLE9BQUEsR0FBQSxVQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsUUFBQSxDQUFBLElBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsYUFBQSxHQUFBLEVBQUEsRUFBQSxLQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLFVBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxVQUFBLENBQUEsYUFBQSxHQUFBLEVBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUdBLFdBQUEsSUFBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ3BDQSxHQUFBLENBQUEsU0FBQSxDQUFBLFdBQUEsRUFBQSxZQUFBO0FBQ0EsV0FBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtBQUNBLG1CQUFBLEVBQUEsNkNBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ0xBLEdBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxJQUFBO0FBQ0EsbUJBQUEsRUFBQSxtREFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxnQkFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxJQUFBO0FBQ0EsbUJBQUEsRUFBQSw2REFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxRQUFBLEVBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtBQUNBLGFBQUEsRUFBQSxFQUFBO0FBQ0EsbUJBQUEsRUFBQSx5Q0FBQTtBQUNBLFlBQUEsRUFBQSxjQUFBLEtBQUEsRUFBQTs7QUFFQSxpQkFBQSxDQUFBLEtBQUEsR0FBQSxDQUNBLEVBQUEsS0FBQSxFQUFBLFFBQUEsRUFBQSxLQUFB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QUEsRUFBQTtBQUNBLDJCQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxHQUFBLEVBQUEsSUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EseUJBQUEsQ0FBQSxJQUFBLEdBQUEsV0FBQSxDQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFVBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxJQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLHlCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLHlCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLDBCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBLENBQUE7O0FBRUEsaUJBQUEsQ0FBQSxZQUFBLEdBQUEsWUFBQTs7Ozs7O0FBTUEscUJBQUEsQ0FBQSxNQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxDQUFBLENBQUE7QUFDQSxxQkFBQSxDQUFBLFFBQUEsR0FBQSxJQUFBLENBQUE7YUFDQSxDQUFBO1NBQ0E7QUFDQSxhQUFBLEVBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7U0FDQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDckRBLEdBQUEsQ0FBQSxTQUFBLENBQUEsVUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsbUJBQUEsRUFBQSxxREFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUEiLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcbndpbmRvdy5hcHAgPSBhbmd1bGFyLm1vZHVsZSgnTVNGVGVtcCcsIFsndWkucm91dGVyJywgJ3VpLmJvb3RzdHJhcCcsICdmc2FQcmVCdWlsdCddKTtcblxuYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHVybFJvdXRlclByb3ZpZGVyLCAkbG9jYXRpb25Qcm92aWRlcikge1xuXG5cdC8vIHRoaXMgbWFrZXMgdGhlICcvdXNlcnMvJyByb3V0ZSBjb3JyZWN0bHkgcmVkaXJlY3QgdG8gJy91c2Vycydcblx0JHVybFJvdXRlclByb3ZpZGVyLnJ1bGUoZnVuY3Rpb24gKCRpbmplY3RvciwgJGxvY2F0aW9uKSB7XG5cblx0XHR2YXIgcmUgPSAvKC4rKShcXC8rKShcXD8uKik/JC9cblx0XHR2YXIgcGF0aCA9ICRsb2NhdGlvbi51cmwoKTtcblxuXHRcdGlmKHJlLnRlc3QocGF0aCkpIHtcblx0XHRcdHJldHVybiBwYXRoLnJlcGxhY2UocmUsICckMSQzJylcblx0XHR9XG5cblx0XHRyZXR1cm4gZmFsc2U7XG5cdH0pO1xuXHQvLyBUaGlzIHR1cm5zIG9mZiBoYXNoYmFuZyB1cmxzICgvI2Fib3V0KSBhbmQgY2hhbmdlcyBpdCB0byBzb21ldGhpbmcgbm9ybWFsICgvYWJvdXQpXG5cdCRsb2NhdGlvblByb3ZpZGVyLmh0bWw1TW9kZSh0cnVlKTtcblx0JHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hdXRoLzpwcm92aWRlcicsIGZ1bmN0aW9uICgpIHtcblx0XHR3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7XG5cdH0pO1xuXHQvLyBJZiB3ZSBnbyB0byBhIFVSTCB0aGF0IHVpLXJvdXRlciBkb2Vzbid0IGhhdmUgcmVnaXN0ZXJlZCwgZ28gdG8gdGhlIFwiL1wiIHVybC5cblx0JHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZSgnLycpO1xuXG59KTtcblxuLy8gVGhpcyBhcHAucnVuIGlzIGZvciBjb250cm9sbGluZyBhY2Nlc3MgdG8gc3BlY2lmaWMgc3RhdGVzLlxuYXBwLnJ1bihmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG5cdC8vIFRoZSBnaXZlbiBzdGF0ZSByZXF1aXJlcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG5cdHZhciBkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoID0gZnVuY3Rpb24gKHN0YXRlKSB7XG5cdFx0cmV0dXJuIHN0YXRlLmRhdGEgJiYgc3RhdGUuZGF0YS5hdXRoZW50aWNhdGU7XG5cdH07XG5cblx0Ly8gJHN0YXRlQ2hhbmdlU3RhcnQgaXMgYW4gZXZlbnQgZmlyZWRcblx0Ly8gd2hlbmV2ZXIgdGhlIHByb2Nlc3Mgb2YgY2hhbmdpbmcgYSBzdGF0ZSBiZWdpbnMuXG5cdCRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uIChldmVudCwgdG9TdGF0ZSwgdG9QYXJhbXMpIHtcblxuXHRcdGlmICghZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCh0b1N0YXRlKSkge1xuXHRcdFx0Ly8gVGhlIGRlc3RpbmF0aW9uIHN0YXRlIGRvZXMgbm90IHJlcXVpcmUgYXV0aGVudGljYXRpb25cblx0XHRcdC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG5cdFx0XHRyZXR1cm47XG5cdFx0fVxuXG5cdFx0aWYgKEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpKSB7XG5cdFx0XHQvLyBUaGUgdXNlciBpcyBhdXRoZW50aWNhdGVkLlxuXHRcdFx0Ly8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cblx0XHRcdHJldHVybjtcblx0XHR9XG5cblx0XHQvLyBDYW5jZWwgbmF2aWdhdGluZyB0byBuZXcgc3RhdGUuXG5cdFx0ZXZlbnQucHJldmVudERlZmF1bHQoKTtcblxuXHRcdEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcblx0XHRcdC8vIElmIGEgdXNlciBpcyByZXRyaWV2ZWQsIHRoZW4gcmVuYXZpZ2F0ZSB0byB0aGUgZGVzdGluYXRpb25cblx0XHRcdC8vICh0aGUgc2Vjb25kIHRpbWUsIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpIHdpbGwgd29yaylcblx0XHRcdC8vIG90aGVyd2lzZSwgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4sIGdvIHRvIFwibG9naW5cIiBzdGF0ZS5cblx0XHRcdGlmICh1c2VyKSB7XG5cdFx0XHRcdCRzdGF0ZS5nbyh0b1N0YXRlLm5hbWUsIHRvUGFyYW1zKTtcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdCRzdGF0ZS5nbygnbG9naW4nKTtcblx0XHRcdH1cblx0XHR9KTtcblxuXHR9KTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhbGVydHMnLCB7XG4gICAgICAgIHVybDogJy9hbGVydHMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2FsZXJ0cy9hbGVydHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdhbGVydEN0cmwnXG4gICAgfSlcbn0pXG5cbmFwcC5jb250cm9sbGVyKCdhbGVydEN0cmwnLCBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5LCAkc2NvcGUsICRzdGF0ZSwgJHJvb3RTY29wZSkge1xuXG4gICAgJHNjb3BlLnNhdmVBbGVydCA9IGZ1bmN0aW9uIChhbGVydCkge1xuICAgICAgICBhbGVydC51cHBlckJvdW5kID0gTnVtYmVyKGFsZXJ0LnVwcGVyQm91bmQpO1xuICAgICAgICBhbGVydC5sb3dlckJvdW5kID0gTnVtYmVyKGFsZXJ0Lmxvd2VyQm91bmQpO1xuICAgICAgICBhbGVydC50ZW1wO1xuICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0ID0gYWxlcnQ7XG4gICAgICAgICRyb290U2NvcGUuYWxlcnRFbnRlcmVkID0gdHJ1ZTtcbiAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgfVxufSlcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAuc3RhdGUoJ2RhdGEnLCB7XG4gICAgICAgIHVybDogJy9kYXRhJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kYXRhL2RhdGEuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIGFsbER3ZWV0cykge1xuICAgICAgICAgICRzY29wZS5kd2VldHMgPSBhbGxEd2VldHM7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIC8vIGZpbmREd2VldHM6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgIC8vICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldEFsbCgpO1xuICAgICAgICAgICAgLy8gfTtcbiAgICAgICAgICAgIGFsbER3ZWV0czogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0QWxsKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KVxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdkb2NzJywge1xuICAgICAgICB1cmw6ICcvZG9jcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvZG9jcy9kb2NzLmh0bWwnXG4gICAgfSk7XG59KTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgICAndXNlIHN0cmljdCc7XG5cbiAgICAvLyBIb3BlIHlvdSBkaWRuJ3QgZm9yZ2V0IEFuZ3VsYXIhIER1aC1kb3kuXG4gICAgaWYgKCF3aW5kb3cuYW5ndWxhcikgdGhyb3cgbmV3IEVycm9yKCdJIGNhblxcJ3QgZmluZCBBbmd1bGFyIScpO1xuXG4gICAgdmFyIGFwcCA9IGFuZ3VsYXIubW9kdWxlKCdmc2FQcmVCdWlsdCcsIFtdKTtcblxuICAgIGFwcC5mYWN0b3J5KCdTb2NrZXQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICghd2luZG93LmlvKSB0aHJvdyBuZXcgRXJyb3IoJ3NvY2tldC5pbyBub3QgZm91bmQhJyk7XG4gICAgICAgIHJldHVybiB3aW5kb3cuaW8od2luZG93LmxvY2F0aW9uLm9yaWdpbik7XG4gICAgfSk7XG5cbiAgICAvLyBBVVRIX0VWRU5UUyBpcyB1c2VkIHRocm91Z2hvdXQgb3VyIGFwcCB0b1xuICAgIC8vIGJyb2FkY2FzdCBhbmQgbGlzdGVuIGZyb20gYW5kIHRvIHRoZSAkcm9vdFNjb3BlXG4gICAgLy8gZm9yIGltcG9ydGFudCBldmVudHMgYWJvdXQgYXV0aGVudGljYXRpb24gZmxvdy5cbiAgICBhcHAuY29uc3RhbnQoJ0FVVEhfRVZFTlRTJywge1xuICAgICAgICBsb2dpblN1Y2Nlc3M6ICdhdXRoLWxvZ2luLXN1Y2Nlc3MnLFxuICAgICAgICBsb2dpbkZhaWxlZDogJ2F1dGgtbG9naW4tZmFpbGVkJyxcbiAgICAgICAgc2lnbnVwU3VjY2VzczogJ2F1dGgtc2lnbnVwLXN1Y2Nlc3MnLFxuICAgICAgICBzaWdudXBGYWlsZWQ6ICdhdXRoLXNpZ251cC1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvL2FkZCBzdWNjZXNzZnVsIHNpZ251cFxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxTaWdudXAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMuc2lnbnVwU3VjY2Vzcyk7XG4gICAgICAgICAgICByZXR1cm4gZGF0YS51c2VyO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gVXNlcyB0aGUgc2Vzc2lvbiBmYWN0b3J5IHRvIHNlZSBpZiBhblxuICAgICAgICAvLyBhdXRoZW50aWNhdGVkIHVzZXIgaXMgY3VycmVudGx5IHJlZ2lzdGVyZWQuXG4gICAgICAgIHRoaXMuaXNBdXRoZW50aWNhdGVkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICEhU2Vzc2lvbi51c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZ2V0TG9nZ2VkSW5Vc2VyID0gZnVuY3Rpb24gKGZyb21TZXJ2ZXIpIHtcblxuICAgICAgICAgICAgLy8gSWYgYW4gYXV0aGVudGljYXRlZCBzZXNzaW9uIGV4aXN0cywgd2VcbiAgICAgICAgICAgIC8vIHJldHVybiB0aGUgdXNlciBhdHRhY2hlZCB0byB0aGF0IHNlc3Npb25cbiAgICAgICAgICAgIC8vIHdpdGggYSBwcm9taXNlLiBUaGlzIGVuc3VyZXMgdGhhdCB3ZSBjYW5cbiAgICAgICAgICAgIC8vIGFsd2F5cyBpbnRlcmZhY2Ugd2l0aCB0aGlzIG1ldGhvZCBhc3luY2hyb25vdXNseS5cblxuICAgICAgICAgICAgLy8gT3B0aW9uYWxseSwgaWYgdHJ1ZSBpcyBnaXZlbiBhcyB0aGUgZnJvbVNlcnZlciBwYXJhbWV0ZXIsXG4gICAgICAgICAgICAvLyB0aGVuIHRoaXMgY2FjaGVkIHZhbHVlIHdpbGwgbm90IGJlIHVzZWQuXG5cbiAgICAgICAgICAgIGlmICh0aGlzLmlzQXV0aGVudGljYXRlZCgpICYmIGZyb21TZXJ2ZXIgIT09IHRydWUpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEud2hlbihTZXNzaW9uLnVzZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNYWtlIHJlcXVlc3QgR0VUIC9zZXNzaW9uLlxuICAgICAgICAgICAgLy8gSWYgaXQgcmV0dXJucyBhIHVzZXIsIGNhbGwgb25TdWNjZXNzZnVsTG9naW4gd2l0aCB0aGUgcmVzcG9uc2UuXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgNDAxIHJlc3BvbnNlLCB3ZSBjYXRjaCBpdCBhbmQgaW5zdGVhZCByZXNvbHZlIHRvIG51bGwuXG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvc2Vzc2lvbicpLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuc2lnbnVwID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL3NpZ251cCcsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bFNpZ251cCk7XG4gICAgICAgIH07XG5cblxuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ1Nlc3Npb24nLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMpIHtcblxuICAgICAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2VsZi5kZXN0cm95KCk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5pZCA9IG51bGw7XG4gICAgICAgIHRoaXMudXNlciA9IG51bGw7XG5cbiAgICAgICAgdGhpcy5jcmVhdGUgPSBmdW5jdGlvbiAoc2Vzc2lvbklkLCB1c2VyKSB7XG4gICAgICAgICAgICB0aGlzLmlkID0gc2Vzc2lvbklkO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gdXNlcjtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmRlc3Ryb3kgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgICAgIHRoaXMudXNlciA9IG51bGw7XG4gICAgICAgIH07XG5cbiAgICB9KTtcblxufSkoKTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnaG9tZScsIHtcbiAgICAgICAgdXJsOiAnLycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvaG9tZS9ob21lLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbigkc2NvcGUsIER3ZWV0RmFjdG9yeSwgbGF0ZXN0VGVtcCwgJHJvb3RTY29wZSwgJHN0YXRlKSB7XG4gICAgICAgICAgICAvL0NyZWF0ZSBhcnJheSBvZiBsYXRlc3QgZHdlZXRzIHRvIGRpc3BsYXkgb24gaG9tZSBzdGF0ZVxuICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMgPSBbXTtcbiAgICAgICAgICAgICRyb290U2NvcGUuaG9tZUFsZXJ0cyA9IFtdO1xuXG4gICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgICAgICAgICAvL0luaXRpYWxpemUgd2l0aCBmaXJzdCBkd2VldFxuICAgICAgICAgICAgRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpXG4gICAgICAgICAgICAudGhlbihmdW5jdGlvbihkd2VldCl7XG4gICAgICAgICAgICAgICAgJHNjb3BlLnByZXZEd2VldCA9IGR3ZWV0O1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIC8vIGJ1dHRvbiBjbGljayBsZWFkcyB0byBhbGVydHMgc3RhdGVcbiAgICAgICAgICAgICRzY29wZS5nb0FsZXJ0cyA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2FsZXJ0cycpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIGxpbmUxID0gbmV3IFRpbWVTZXJpZXMoKTtcbiAgICAgICAgICAgIHZhciBsaW5lMiA9IG5ldyBUaW1lU2VyaWVzKCk7XG5cbiAgICAgICAgICAgIC8vIGRlZmF1bHQgdGVtcGVyYXR1cmUgcmFuZ2UgaXMgNTAtOTAgZm9yIGRlbW8gcHVycG9zZXNcbiAgICAgICAgICAgIGlmKCEkcm9vdFNjb3BlLmFsZXJ0KSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS5hbGVydCA9IHt9O1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuYWxlcnQubG93ZXJCb3VuZCA9IDUwO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuYWxlcnQudXBwZXJCb3VuZCA9IDkwO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBDaGVjayBldmVyeSBoYWxmIHNlY29uZCB0byBzZWUgaWYgdGhlIGxhc3QgZHdlZXQgaXMgbmV3LCB0aGVuIHB1c2ggdG8gaG9tZUR3ZWV0cywgdGhlbiBwbG90XG4gICAgICAgICAgICBpZiAoJHJvb3RTY29wZS5hbGVydCkge1xuICAgICAgICAgICAgICAgIHNldEludGVydmFsKGZ1bmN0aW9uKCkge1xuICAgICAgICAgICAgICAgICAgICBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KClcbiAgICAgICAgICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24oZHdlZXQpe1xuICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmxhc3REd2VldCA9IGR3ZWV0O1xuICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgIHZhciByYW5kb21UZW1wID0gTWF0aC5yYW5kb20oKSoyMCs2MDtcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmICgkc2NvcGUucHJldkR3ZWV0LmNyZWF0ZWQgIT0gJHNjb3BlLmxhc3REd2VldC5jcmVhdGVkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMucHVzaCgkc2NvcGUubGFzdER3ZWV0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUucHJldkR3ZWV0ID0gJHNjb3BlLmxhc3REd2VldDtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaW5lMS5hcHBlbmQobmV3IERhdGUoKS5nZXRUaW1lKCksICRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAvL1JhbmRvbSBwbG90IHRvIGNoZWNrIHRoYXQgdGhlIGdyYXBoIGlzIHdvcmtpbmdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBsaW5lMi5hcHBlbmQobmV3IERhdGUoKS5nZXRUaW1lKCksIHJhbmRvbVRlbXApO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgLy9EZXRlY3QgaWYgdGhlIHRlbXBlcmF0dXJlIGJyZWFrcyBvdXQgb2Ygc2FmZSByYW5nZVxuICAgICAgICAgICAgICAgICAgICAgICAgaWYgKCRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddID4gJHJvb3RTY29wZS5hbGVydC51cHBlckJvdW5kIHx8ICRzY29wZS5sYXN0RHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddIDwgJHJvb3RTY29wZS5hbGVydC5sb3dlckJvdW5kKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgY29uc29sZS5sb2coJ2JyZWFrIGluIGNvbGQgY2hhaW4nKVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBjdXJyRGF0ZSA9IG5ldyBEYXRlKCk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJUaW1lID0gY3VyckRhdGUudG9TdHJpbmcoKS5zbGljZSgxNik7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5hbGVydC50aW1lID0gY3VyclRpbWU7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5hbGVydC50ZW1wID0gJHNjb3BlLmxhc3REd2VldC5jb250ZW50WydhaU91dHNpZGVUZW1wX2RlZ3JlZXNGJ107XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgRHdlZXRGYWN0b3J5LnBvc3RBbGVydCgkcm9vdFNjb3BlLmFsZXJ0KVxuICAgICAgICAgICAgICAgICAgICAgICAgICAgIC50aGVuIChmdW5jdGlvbiAocG9zdGVkQWxlcnQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHJvb3RTY29wZS5ob21lQWxlcnRzLnB1c2gocG9zdGVkQWxlcnQpO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuZXJyb3IgPSAnQnJlYWsgaW4gY29sZCBjaGFpbiBkZXRlY3RlZCEhJ1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0pXG4gICAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICAgICAgICAvL0RldGVjdCBpZiB0aGUgdGVtcGVyYXR1cmUgYnJlYWtzIG91dCBvZiBzYWZlIHJhbmdlXG4gICAgICAgICAgICAvL1RVUk4gT04gVE8gREVNT05TVFJBVEUgQlJFQUsgSU4gQ09MRCBDSEFJTiBBTEVSVCAmIEVNQUlMIEZFQVRVUkVcbiAgICAgICAgICAgICAgICAgICAgICAgIGlmIChyYW5kb21UZW1wID4gJHJvb3RTY29wZS5hbGVydC51cHBlckJvdW5kIHx8IHJhbmRvbVRlbXAgPCAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICBjb25zb2xlLmxvZygnYnJlYWsgaW4gY29sZCBjaGFpbiAyJyk7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGN1cnJEYXRlID0gbmV3IERhdGUoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY3VyclRpbWUgPSBjdXJyRGF0ZS50b1N0cmluZygpLnNsaWNlKDE2KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRpbWUgPSBjdXJyVGltZTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkcm9vdFNjb3BlLmFsZXJ0LnRlbXAgPSByYW5kb21UZW1wO1xuICAgICAgICAgICAgICAgICAgICAgICAgICAgIER3ZWV0RmFjdG9yeS5wb3N0QWxlcnQoJHJvb3RTY29wZS5hbGVydClcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAudGhlbiAoZnVuY3Rpb24gKHBvc3RlZEFsZXJ0KSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICRyb290U2NvcGUuaG9tZUFsZXJ0cy5wdXNoKHBvc3RlZEFsZXJ0KTtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0JyZWFrIGluIGNvbGQgY2hhaW4gZGV0ZWN0ZWQhISdcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICB9KVxuICAgICAgICAgICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgICAgICAgICB3aGlsZSgkc2NvcGUuaG9tZUR3ZWV0cy5sZW5ndGggPiAxMDApIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAkc2NvcGUuaG9tZUR3ZWV0cy5zaGlmdCgpO1xuICAgICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgICAgd2hpbGUoJHNjb3BlLmhvbWVBbGVydHMubGVuZ3RoID4gMTAwKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgICAgJHNjb3BlLmhvbWVBbGVydHMuc2hpZnQoKTtcbiAgICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgfSlcbiAgICAgICAgICAgICAgICB9LCA1MDApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvL01ha2UgYSBzbW9vdGhpZSBjaGFydCB3aXRoIGFlc3RoZXRpY2FsbHkgcGxlYXNpbmcgcHJvcGVydGllc1xuICAgICAgICAgICAgdmFyIHNtb290aGllID0gbmV3IFNtb290aGllQ2hhcnQoe1xuICAgICAgICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoNjMsIDE2MCwgMTgyKScsXG4gICAgICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYig0LCA1LCA5MSknLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6IDEsXG4gICAgICAgICAgICAgICAgICAgIG1pbGxpc1BlckxpbmU6IDUwMCxcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWxTZWN0aW9uczogNFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgbWF4VmFsdWU6ICRyb290U2NvcGUuYWxlcnQudXBwZXJCb3VuZCAqIDEuMDAzLFxuICAgICAgICAgICAgICAgIG1pblZhbHVlOiAkcm9vdFNjb3BlLmFsZXJ0Lmxvd2VyQm91bmQgKiAwLjk5NyxcbiAgICAgICAgICAgICAgICAvLyBtYXhWYWx1ZVNjYWxlOiAxLjAxLFxuICAgICAgICAgICAgICAgIC8vIG1pblZhbHVlU2NhbGU6IDEuMDIsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wRm9ybWF0dGVyOlNtb290aGllQ2hhcnQudGltZUZvcm1hdHRlcixcbiAgICAgICAgICAgICAgICAvL1RoZSByYW5nZSBvZiBhY2NlcHRhYmxlIHRlbXBlcmF0dXJlcyB2aXN1YWxpemVkXG4gICAgICAgICAgICAgICAgLy9TaG91bGQgY2hhbmdlICd2YWx1ZScgYWNjb3JkaW5nbHlcbiAgICAgICAgICAgICAgICBob3Jpem9udGFsTGluZXM6W3tcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6JyM4ODAwMDAnLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6NSxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6ICgkcm9vdFNjb3BlLmFsZXJ0LnVwcGVyQm91bmQgfHwgNzApXG4gICAgICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgICAgICBjb2xvcjonIzg4MDAwMCcsXG4gICAgICAgICAgICAgICAgICAgIGxpbmVXaWR0aDo1LFxuICAgICAgICAgICAgICAgICAgICB2YWx1ZTogKCRyb290U2NvcGUuYWxlcnQubG93ZXJCb3VuZCB8fCA2OClcbiAgICAgICAgICAgICAgICB9XVxuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTEsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigwLCAyNTUsIDApJyxcbiAgICAgICAgICAgICAgICBmaWxsU3R5bGU6ICdyZ2JhKDAsIDI1NSwgMCwgMC40KScsXG4gICAgICAgICAgICAgICAgbGluZVdpZHRoOiAzXG4gICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIHNtb290aGllLmFkZFRpbWVTZXJpZXMobGluZTIsIHtcbiAgICAgICAgICAgICAgICBzdHJva2VTdHlsZTogJ3JnYigyNTUsIDAsIDI1NSknLFxuICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYmEoMjU1LCAwLCAyNTUsIDAuMyknLFxuICAgICAgICAgICAgICAgIGxpbmVXaWR0aDogM1xuICAgICAgICAgICAgfSk7XG5cbiAgICAgICAgICAgIHNtb290aGllLnN0cmVhbVRvKGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFwiY2hhcnRcIiksIDMwMCk7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGxhdGVzdFRlbXA6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpXG4gICAgICAgICAgICAgICAgLnRoZW4oIGZ1bmN0aW9uIChkd2VldCkge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gZHdlZXQuY29udGVudFsnYWlPdXRzaWRlVGVtcF9kZWdyZWVzRiddO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSk7XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbGF0ZXN0Jywge1xuICAgICAgICB1cmw6ICcvZGF0YS9sYXRlc3QnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2xhdGVzdC9sYXRlc3QuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIGxhdGVzdER3ZWV0KSB7XG4gICAgICAgICAgJHNjb3BlLmxhdGVzdER3ZWV0ID0gbGF0ZXN0RHdlZXQ7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIGxhdGVzdER3ZWV0OiBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIER3ZWV0RmFjdG9yeS5nZXRMYXRlc3QoKTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pXG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ2xvZ2luJywge1xuICAgIHVybDogJy9sb2dpbicsXG4gICAgdGVtcGxhdGVVcmw6ICdqcy9sb2dpbi9sb2dpbi5odG1sJyxcbiAgICBjb250cm9sbGVyOiAnTG9naW5DdHJsJ1xuICB9KTtcbn0pO1xuXG5hcHAuY29udHJvbGxlcignTG9naW5DdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICRzY29wZS5sb2dpbiA9IHt9O1xuICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICRzY29wZS5zZW5kTG9naW4gPSBmdW5jdGlvbiAobG9naW5JbmZvKSB7XG5cbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgQXV0aFNlcnZpY2UubG9naW4obG9naW5JbmZvKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgIGlmKHVzZXIubmV3UGFzcykgJHN0YXRlLmdvKCdyZXNldFBhc3MnLCB7J3VzZXJJZCc6IHVzZXIuX2lkfSk7XG4gICAgICBlbHNlICRzdGF0ZS5nbygnaG9tZScpO1xuICAgIH0pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICRzY29wZS5lcnJvciA9ICdJbnZhbGlkIGxvZ2luIGNyZWRlbnRpYWxzLic7XG4gICAgfSk7XG4gIH07XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAuc3RhdGUoJ3Jlc2V0UGFzcycsIHtcbiAgICAgICAgdXJsOiAnL3Jlc2V0Lzp1c2VySWQnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3Jlc2V0UGFzcy9yZXNldFBhc3MuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdSZXNldEN0cmwnXG4gICAgfSk7XG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1Jlc2V0Q3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIFVzZXJGYWN0b3J5LCAkc3RhdGVQYXJhbXMsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5yZXNldFBhc3MgPSBmdW5jdGlvbiAobmV3UGFzcykge1xuICAgICAgICBVc2VyRmFjdG9yeS5lZGl0KCRzdGF0ZVBhcmFtcy51c2VySWQsIHsnbmV3UGFzcyc6IGZhbHNlLCAncGFzc3dvcmQnOiBuZXdQYXNzfSlcbiAgICAgICAgLnRoZW4oIGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICBBdXRoU2VydmljZS5sb2dpbih7ZW1haWw6IHVzZXIuZW1haWwsIHBhc3N3b3JkOiBuZXdQYXNzfSlcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgICAgICB9KTtcbiAgICAgICAgfSlcbiAgICB9XG59KVxuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcblxuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdzaWdudXAnLCB7XG4gICAgICAgIHVybDogJy9zaWdudXAnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL3NpZ251cC9zaWdudXAuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdTaWdudXBDdHJsJ1xuICAgIH0pO1xuXG59KTtcblxuYXBwLmNvbnRyb2xsZXIoJ1NpZ251cEN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgICAkc2NvcGUuZXJyb3IgPSBudWxsO1xuXG4gICAgJHNjb3BlLnNlbmRTaWdudXA9IGZ1bmN0aW9uIChzaWdudXBJbmZvKSB7XG4gICAgICAgICRzY29wZS5lcnJvciA9IG51bGw7XG4gICAgICAgIEF1dGhTZXJ2aWNlLnNpZ251cChzaWdudXBJbmZvKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzY29wZS5lcnJvciA9ICdFbWFpbCBpcyB0YWtlbiEnO1xuICAgICAgICB9KTtcblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcil7XG4gICRzdGF0ZVByb3ZpZGVyXG4gIC5zdGF0ZSgndXNlcicsIHtcbiAgICB1cmw6ICcvdXNlci86dXNlcklkJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy91c2VyL3VzZXIuaHRtbCcsXG4gICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgZmluZFVzZXIpIHtcbiAgICAgICRzY29wZS51c2VyID0gZmluZFVzZXI7XG4gICAgfSxcbiAgICByZXNvbHZlOiB7XG4gICAgICBmaW5kVXNlcjogZnVuY3Rpb24gKCRzdGF0ZVBhcmFtcywgVXNlckZhY3RvcnkpIHtcbiAgICAgICAgcmV0dXJuIFVzZXJGYWN0b3J5LmdldEJ5SWQoJHN0YXRlUGFyYW1zLnVzZXJJZClcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24odXNlcil7XG4gICAgICAgICAgcmV0dXJuIHVzZXI7XG4gICAgICAgIH0pO1xuICAgIH1cbiAgICB9XG4gIH0pO1xufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKXtcblx0JHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3VzZXJzJywge1xuXHRcdHVybDogJy91c2VycycsXG5cdFx0dGVtcGxhdGVVcmw6ICcvanMvdXNlcnMvdXNlcnMuaHRtbCcsXG5cdFx0cmVzb2x2ZTp7XG5cdFx0XHR1c2VyczogZnVuY3Rpb24oVXNlckZhY3Rvcnkpe1xuXHRcdFx0XHRyZXR1cm4gVXNlckZhY3RvcnkuZ2V0QWxsKCk7XG5cdFx0XHR9XG5cdFx0fSxcblx0XHRjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCB1c2VycywgU2Vzc2lvbiwgJHN0YXRlKSB7XG5cdFx0XHQkc2NvcGUudXNlcnMgPSB1c2VycztcblxuICAgICAgICAgICAgLy9XSFkgTk9UIE9OIFNFU1NJT04/Pz8/XG5cdFx0XHQvLyBpZiAoIVNlc3Npb24udXNlciB8fCAhU2Vzc2lvbi51c2VyLmlzQWRtaW4pe1xuXHRcdFx0Ly8gXHQkc3RhdGUuZ28oJ2hvbWUnKTtcblx0XHRcdC8vIH1cblx0XHR9XG59KTtcbn0pO1xuIiwiYXBwLmZhY3RvcnkoJ0R3ZWV0RmFjdG9yeScsIGZ1bmN0aW9uICgkaHR0cCkge1xuICAgIHZhciBEd2VldHMgPSBmdW5jdGlvbihwcm9wcykge1xuICAgICAgICBhbmd1bGFyLmV4dGVuZCh0aGlzLCBwcm9wcyk7XG4gICAgfTtcblxuICAgIER3ZWV0cy5nZXRBbGwgPSBmdW5jdGlvbiAoKXtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9kYXRhJylcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24gKHJlc3BvbnNlKXtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KVxuXHR9O1xuXG4gICAgRHdlZXRzLmdldExhdGVzdCA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2FwaS9kYXRhL2xhdGVzdCcpXG4gICAgICAgIC50aGVuIChmdW5jdGlvbiAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHJldHVybiByZXNwb25zZS5kYXRhO1xuICAgICAgICB9KVxuICAgIH07XG5cbiAgICBEd2VldHMucG9zdEFsZXJ0ID0gZnVuY3Rpb24gKGFsZXJ0KSB7XG4gICAgICAgIHJldHVybiAkaHR0cC5wb3N0KCcvYXBpL2FsZXJ0cycsIGFsZXJ0KVxuICAgICAgICAudGhlbiAoIGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pO1xuICAgIH07XG5cbiAgICByZXR1cm4gRHdlZXRzO1xufSlcbiIsImFwcC5mYWN0b3J5KCdVc2VyRmFjdG9yeScsIGZ1bmN0aW9uKCRodHRwKXtcblxuXHR2YXIgVXNlciA9IGZ1bmN0aW9uKHByb3BzKXtcblx0XHRhbmd1bGFyLmV4dGVuZCh0aGlzLCBwcm9wcyk7XG5cdH07XG5cblx0VXNlci5nZXRBbGwgPSBmdW5jdGlvbiAoKXtcblx0XHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL3VzZXJzJylcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXHRVc2VyLmdldEJ5SWQgPSBmdW5jdGlvbiAoaWQpIHtcblx0XHRyZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL3VzZXJzLycgKyBpZClcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXHRVc2VyLmVkaXQgPSBmdW5jdGlvbiAoaWQsIHByb3BzKSB7XG5cdFx0cmV0dXJuICRodHRwLnB1dCgnL2FwaS91c2Vycy8nICsgaWQsIHByb3BzKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cdFVzZXIuZGVsZXRlID0gZnVuY3Rpb24gKGlkKSB7XG5cdFx0cmV0dXJuICRodHRwLmRlbGV0ZSgnL2FwaS91c2Vycy8nICsgaWQpXG5cdFx0LnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0XHRyZXR1cm4gcmVzcG9uc2UuZGF0YTtcblx0XHR9KTtcblx0fTtcblxuXG5cdHJldHVybiBVc2VyO1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCdkd2VldExpc3QnLCBmdW5jdGlvbigpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvY29tbW9uL2RpcmVjdGl2ZXMvZHdlZXQvZHdlZXQtbGlzdC5odG1sJ1xuICB9O1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKFwiZWRpdEJ1dHRvblwiLCBmdW5jdGlvbiAoKSB7XG5cdHJldHVybiB7XG5cdFx0cmVzdHJpY3Q6ICdFQScsXG5cdFx0dGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9lZGl0LWJ1dHRvbi9lZGl0LWJ1dHRvbi5odG1sJyxcblx0fTtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZShcImVkaXRQYXNzQnV0dG9uXCIsIGZ1bmN0aW9uICgpIHtcblx0cmV0dXJuIHtcblx0XHRyZXN0cmljdDogJ0VBJyxcblx0XHR0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2VkaXQtcGFzcy1idXR0b24vZWRpdC1wYXNzLWJ1dHRvbi5odG1sJyxcblx0fTtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgnbmF2YmFyJywgZnVuY3Rpb24gKCRyb290U2NvcGUsIEF1dGhTZXJ2aWNlLCBBVVRIX0VWRU5UUywgJHN0YXRlKSB7XG5cbiAgICByZXR1cm4ge1xuICAgICAgICByZXN0cmljdDogJ0UnLFxuICAgICAgICBzY29wZToge30sXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvbmF2YmFyL25hdmJhci5odG1sJyxcbiAgICAgICAgbGluazogZnVuY3Rpb24gKHNjb3BlKSB7XG5cbiAgICAgICAgICAgIHNjb3BlLml0ZW1zID0gW1xuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdBbGVydHMnLCBzdGF0ZTogJ2FsZXJ0cycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRGF0YScsIHN0YXRlOiAnZGF0YScgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnTGF0ZXN0Jywgc3RhdGU6ICdsYXRlc3QnIH0sXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ1VzZXJzJywgc3RhdGU6ICd1c2VycycgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnRG9jdW1lbnRhdGlvbicsIHN0YXRlOiAnZG9jcycgfVxuICAgICAgICAgICAgXTtcblxuICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG5cbiAgICAgICAgICAgIHNjb3BlLmlzTG9nZ2VkSW4gPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgc2NvcGUubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ291dCgpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgc2V0VXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBBdXRoU2VydmljZS5nZXRMb2dnZWRJblVzZXIoKS50aGVuKGZ1bmN0aW9uICh1c2VyKSB7XG4gICAgICAgICAgICAgICAgICAgIHNjb3BlLnVzZXIgPSB1c2VyO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgfTtcblxuICAgICAgICAgICAgdmFyIHJlbW92ZVVzZXIgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IG51bGw7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzZXRVc2VyKCk7XG5cbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ2luU3VjY2Vzcywgc2V0VXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zaWdudXBTdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLmxvZ291dFN1Y2Nlc3MsIHJlbW92ZVVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMuc2Vzc2lvblRpbWVvdXQsIHJlbW92ZVVzZXIpO1xuXG4gICAgICAgIH1cblxuICAgIH07XG5cbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgndXNlckRldGFpbCcsIGZ1bmN0aW9uKFVzZXJGYWN0b3J5LCAkc3RhdGVQYXJhbXMsICRzdGF0ZSwgU2Vzc2lvbil7XG4gIHJldHVybiB7XG5cdHJlc3RyaWN0OiAnRScsXG5cdHRlbXBsYXRlVXJsOiAnL2pzL2NvbW1vbi9kaXJlY3RpdmVzL3VzZXIvdXNlci1kZXRhaWwvdXNlci1kZXRhaWwuaHRtbCcsXG5cdGxpbms6IGZ1bmN0aW9uIChzY29wZSl7XG5cdFx0c2NvcGUuaXNEZXRhaWwgPSB0cnVlO1xuXHRcdHNjb3BlLmlzQWRtaW4gPSBTZXNzaW9uLnVzZXIuaXNBZG1pbjtcblx0XHRzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuICAgICAgICBzY29wZS5lZGl0UGFzcyA9IGZhbHNlO1xuXG4gICAgICAgIC8vRklYIFRISVMgTElORVxuICAgICAgICBpZiAoc2NvcGUudXNlciA9IFNlc3Npb24udXNlcikgc2NvcGUuaXNPd25lciA9IHRydWVcblxuXHRcdHNjb3BlLmVuYWJsZUVkaXQgPSBmdW5jdGlvbiAoKSB7XG5cdFx0XHRzY29wZS5jYWNoZWQgPSBhbmd1bGFyLmNvcHkoc2NvcGUudXNlcik7XG5cdFx0XHRzY29wZS5lZGl0TW9kZSA9IHRydWU7XG5cdFx0fTtcblx0XHRzY29wZS5jYW5jZWxFZGl0ID0gZnVuY3Rpb24oKXtcblx0XHRcdHNjb3BlLnVzZXIgPSBhbmd1bGFyLmNvcHkoc2NvcGUuY2FjaGVkKTtcblx0XHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgICAgICBzY29wZS5lZGl0UGFzcz0gZmFsc2U7XG5cdFx0fTtcblx0XHRzY29wZS5zYXZlVXNlciA9IGZ1bmN0aW9uICh1c2VyKSB7XG5cdFx0XHRVc2VyRmFjdG9yeS5lZGl0KHVzZXIuX2lkLCB1c2VyKVxuXHRcdFx0LnRoZW4oZnVuY3Rpb24gKHVwZGF0ZWRVc2VyKSB7XG5cdFx0XHRcdHNjb3BlLnVzZXIgPSB1cGRhdGVkVXNlcjtcblx0XHRcdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICBzY29wZS5lZGl0UGFzcz0gZmFsc2U7XG5cdFx0XHR9KTtcblx0XHR9O1xuXHRcdHNjb3BlLmRlbGV0ZVVzZXIgPSBmdW5jdGlvbih1c2VyKXtcblx0XHRcdFVzZXJGYWN0b3J5LmRlbGV0ZSh1c2VyKVxuXHRcdFx0LnRoZW4oZnVuY3Rpb24oKXtcblx0XHRcdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICBzY29wZS5lZGl0UGFzcz0gZmFsc2U7XG5cdFx0XHRcdCRzdGF0ZS5nbygnaG9tZScpO1xuXHRcdFx0fSk7XG5cdFx0fTtcblxuICAgICAgICBzY29wZS5wYXNzd29yZEVkaXQgPSBmdW5jdGlvbigpe1xuICAgICAgICAgICAgLy8gVXNlckZhY3RvcnkuZWRpdChpZCwgeyduZXdQYXNzJzogdHJ1ZX0pXG4gICAgICAgICAgICAvLyAudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAvLyAgICAgLy8gc2NvcGUubmV3UGFzcyA9IHRydWU7XG4gICAgICAgICAgICAvLyAgICAgc2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgIC8vIH0pO1xuICAgICAgICAgICAgc2NvcGUuY2FjaGVkID0gYW5ndWxhci5jb3B5KHNjb3BlLnVzZXIpO1xuICAgICAgICAgICAgc2NvcGUuZWRpdFBhc3MgPSB0cnVlO1xuICAgICAgICB9O1xuXHR9LFxuXHRzY29wZToge1xuXHRcdHVzZXI6IFwiPVwiXG5cdH1cbiAgfTtcbn0pO1xuIiwiYXBwLmRpcmVjdGl2ZSgndXNlckxpc3QnLCBmdW5jdGlvbigpe1xuICByZXR1cm4ge1xuICAgIHJlc3RyaWN0OiAnRScsXG4gICAgdGVtcGxhdGVVcmw6ICcvanMvY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWxpc3QvdXNlci1saXN0Lmh0bWwnXG4gIH07XG59KTtcbiJdLCJzb3VyY2VSb290IjoiL3NvdXJjZS8ifQ==
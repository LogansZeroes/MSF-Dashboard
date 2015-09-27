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

app.controller('alertCtrl', function (DweetFactory, $scope, $state) {
    $scope.sendAlert = function (alert) {
        DweetFactory.postAlert(alert).then(function (postedAlert) {
            $state.go('home');
        });
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
        controller: function controller($scope, DweetFactory, latestTemp) {
            //Create array of latest dweets to display on home state
            $scope.homeDweets = [];

            //Initialize with first dweet
            DweetFactory.getLatest().then(function (dweet) {
                $scope.prevDweet = dweet;
            });

            var line1 = new TimeSeries();
            var line2 = new TimeSeries();

            //Check every half second to see if the last dweet is new, then push to homeDweets, then plot
            // setInterval(function() {
            //     DweetFactory.getLatest()
            //     .then(function(dweet){
            //         $scope.lastDweet = dweet;
            //     })
            //     .then(function() {
            //         if ($scope.prevDweet.created != $scope.lastDweet.created) {
            //             $scope.homeDweets.push($scope.lastDweet);
            //             $scope.prevDweet = $scope.lastDweet;
            //             line1.append(new Date().getTime(), $scope.lastDweet.content['Temperature']);
            //             //Random plot to check that the graph is working
            //             line2.append(new Date().getTime(), Math.floor(Math.random()*4+70));
            //         }
            //         while($scope.homeDweets.length > 100) {
            //             $scope.homeDweets.shift();
            //         }
            //     })
            //
            // }, 100);

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
                maxValueScale: 1.01,
                minValueScale: 1.02,
                timestampFormatter: SmoothieChart.timeFormatter,
                //The range of acceptable temperatures visualized
                //Should change 'value' accordingly
                horizontalLines: [{
                    color: '#880000',
                    lineWidth: 5,
                    value: latestTemp * 1.005 || 70
                }, {
                    color: '#880000',
                    lineWidth: 5,
                    value: latestTemp * 0.99 || 68
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
                    return dweet.content['Temperature'];
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

app.directive("editPassButton", function () {
    return {
        restrict: 'EA',
        templateUrl: 'js/common/directives/edit-pass-button/edit-pass-button.html'
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbImFwcC5qcyIsImFsZXJ0cy9hbGVydHMuanMiLCJkYXRhL2RhdGEuanMiLCJkb2NzL2RvY3MuanMiLCJmc2EvZnNhLXByZS1idWlsdC5qcyIsImhvbWUvaG9tZS5qcyIsImxhdGVzdC9sYXRlc3QuanMiLCJsb2dpbi9sb2dpbi5qcyIsInJlc2V0UGFzcy9yZXNldFBhc3MuanMiLCJzaWdudXAvc2lnbnVwLmpzIiwidXNlci91c2VyLmpzIiwidXNlcnMvdXNlcnMuanMiLCJjb21tb24vZmFjdG9yaWVzL2R3ZWV0LWZhY3RvcnkuanMiLCJjb21tb24vZmFjdG9yaWVzL3VzZXItZmFjdG9yeS5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL2R3ZWV0L2R3ZWV0LWxpc3QuanMiLCJjb21tb24vZGlyZWN0aXZlcy9lZGl0LWJ1dHRvbi9lZGl0LWJ1dHRvbi5qcyIsImNvbW1vbi9kaXJlY3RpdmVzL25hdmJhci9uYXZiYXIuanMiLCJjb21tb24vZGlyZWN0aXZlcy9lZGl0LXBhc3MtYnV0dG9uL2VkaXQtcGFzcy1idXR0b24uanMiLCJjb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItZGV0YWlsL3VzZXItZGV0YWlsLmpzIiwiY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWxpc3QvdXNlci1saXN0LmpzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLFlBQUEsQ0FBQTtBQUNBLE1BQUEsQ0FBQSxHQUFBLEdBQUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxTQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsY0FBQSxFQUFBLGFBQUEsQ0FBQSxDQUFBLENBQUE7O0FBRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGtCQUFBLEVBQUEsaUJBQUEsRUFBQTs7O0FBR0Esc0JBQUEsQ0FBQSxJQUFBLENBQUEsVUFBQSxTQUFBLEVBQUEsU0FBQSxFQUFBOztBQUVBLFlBQUEsRUFBQSxHQUFBLG1CQUFBLENBQUE7QUFDQSxZQUFBLElBQUEsR0FBQSxTQUFBLENBQUEsR0FBQSxFQUFBLENBQUE7O0FBRUEsWUFBQSxFQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLE9BQUEsQ0FBQSxFQUFBLEVBQUEsTUFBQSxDQUFBLENBQUE7U0FDQTs7QUFFQSxlQUFBLEtBQUEsQ0FBQTtLQUNBLENBQUEsQ0FBQTs7QUFFQSxxQkFBQSxDQUFBLFNBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsSUFBQSxDQUFBLGlCQUFBLEVBQUEsWUFBQTtBQUNBLGNBQUEsQ0FBQSxRQUFBLENBQUEsTUFBQSxFQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsc0JBQUEsQ0FBQSxTQUFBLENBQUEsR0FBQSxDQUFBLENBQUE7Q0FFQSxDQUFBLENBQUE7OztBQUdBLEdBQUEsQ0FBQSxHQUFBLENBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLE1BQUEsRUFBQTs7O0FBR0EsUUFBQSw0QkFBQSxHQUFBLFNBQUEsNEJBQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxJQUFBLElBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxZQUFBLENBQUE7S0FDQSxDQUFBOzs7O0FBSUEsY0FBQSxDQUFBLEdBQUEsQ0FBQSxtQkFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBLE9BQUEsRUFBQSxRQUFBLEVBQUE7O0FBRUEsWUFBQSxDQUFBLDRCQUFBLENBQUEsT0FBQSxDQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7O0FBRUEsWUFBQSxXQUFBLENBQUEsZUFBQSxFQUFBLEVBQUE7OztBQUdBLG1CQUFBO1NBQ0E7OztBQUdBLGFBQUEsQ0FBQSxjQUFBLEVBQUEsQ0FBQTs7QUFFQSxtQkFBQSxDQUFBLGVBQUEsRUFBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTs7OztBQUlBLGdCQUFBLElBQUEsRUFBQTtBQUNBLHNCQUFBLENBQUEsRUFBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLEVBQUEsUUFBQSxDQUFBLENBQUE7YUFDQSxNQUFBO0FBQ0Esc0JBQUEsQ0FBQSxFQUFBLENBQUEsT0FBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUEsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUNuRUEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxDQUFBLFFBQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxTQUFBO0FBQ0EsbUJBQUEsRUFBQSx1QkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLFlBQUEsRUFBQSxNQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0EsVUFBQSxDQUFBLFNBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLG9CQUFBLENBQUEsU0FBQSxDQUFBLEtBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNmQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLE9BQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEsU0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxNQUFBLEdBQUEsU0FBQSxDQUFBO1NBQ0E7QUFDQSxlQUFBLEVBQUE7Ozs7QUFJQSxxQkFBQSxFQUFBLG1CQUFBLFlBQUEsRUFBQTtBQUNBLHVCQUFBLFlBQUEsQ0FBQSxNQUFBLEVBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDakJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxNQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsT0FBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsQ0FBQSxZQUFBOztBQUVBLGdCQUFBLENBQUE7OztBQUdBLFFBQUEsQ0FBQSxNQUFBLENBQUEsT0FBQSxFQUFBLE1BQUEsSUFBQSxLQUFBLENBQUEsd0JBQUEsQ0FBQSxDQUFBOztBQUVBLFFBQUEsR0FBQSxHQUFBLE9BQUEsQ0FBQSxNQUFBLENBQUEsYUFBQSxFQUFBLEVBQUEsQ0FBQSxDQUFBOztBQUVBLE9BQUEsQ0FBQSxPQUFBLENBQUEsUUFBQSxFQUFBLFlBQUE7QUFDQSxZQUFBLENBQUEsTUFBQSxDQUFBLEVBQUEsRUFBQSxNQUFBLElBQUEsS0FBQSxDQUFBLHNCQUFBLENBQUEsQ0FBQTtBQUNBLGVBQUEsTUFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQSxDQUFBOzs7OztBQUtBLE9BQUEsQ0FBQSxRQUFBLENBQUEsYUFBQSxFQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLG1CQUFBLEVBQUEsbUJBQUE7QUFDQSxxQkFBQSxFQUFBLHFCQUFBO0FBQ0Esb0JBQUEsRUFBQSxvQkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7QUFDQSxzQkFBQSxFQUFBLHNCQUFBO0FBQ0Esd0JBQUEsRUFBQSx3QkFBQTtBQUNBLHFCQUFBLEVBQUEscUJBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxpQkFBQSxFQUFBLFVBQUEsVUFBQSxFQUFBLEVBQUEsRUFBQSxXQUFBLEVBQUE7QUFDQSxZQUFBLFVBQUEsR0FBQTtBQUNBLGVBQUEsRUFBQSxXQUFBLENBQUEsZ0JBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGFBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7QUFDQSxlQUFBLEVBQUEsV0FBQSxDQUFBLGNBQUE7U0FDQSxDQUFBO0FBQ0EsZUFBQTtBQUNBLHlCQUFBLEVBQUEsdUJBQUEsUUFBQSxFQUFBO0FBQ0EsMEJBQUEsQ0FBQSxVQUFBLENBQUEsVUFBQSxDQUFBLFFBQUEsQ0FBQSxNQUFBLENBQUEsRUFBQSxRQUFBLENBQUEsQ0FBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsUUFBQSxDQUFBLENBQUE7YUFDQTtTQUNBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGFBQUEsRUFBQTtBQUNBLHFCQUFBLENBQUEsWUFBQSxDQUFBLElBQUEsQ0FBQSxDQUNBLFdBQUEsRUFDQSxVQUFBLFNBQUEsRUFBQTtBQUNBLG1CQUFBLFNBQUEsQ0FBQSxHQUFBLENBQUEsaUJBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBLENBQUE7O0FBRUEsT0FBQSxDQUFBLE9BQUEsQ0FBQSxhQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUEsT0FBQSxFQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUEsRUFBQSxFQUFBOztBQUVBLGlCQUFBLGlCQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsZ0JBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7QUFDQSxtQkFBQSxDQUFBLE1BQUEsQ0FBQSxJQUFBLENBQUEsRUFBQSxFQUFBLElBQUEsQ0FBQSxJQUFBLENBQUEsQ0FBQTtBQUNBLHNCQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsQ0FBQSxZQUFBLENBQUEsQ0FBQTtBQUNBLG1CQUFBLElBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQTs7O0FBR0EsaUJBQUEsa0JBQUEsQ0FBQSxRQUFBLEVBQUE7QUFDQSxnQkFBQSxJQUFBLEdBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtBQUNBLG1CQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsQ0FBQSxFQUFBLEVBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO0FBQ0Esc0JBQUEsQ0FBQSxVQUFBLENBQUEsV0FBQSxDQUFBLGFBQUEsQ0FBQSxDQUFBO0FBQ0EsbUJBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBOzs7O0FBSUEsWUFBQSxDQUFBLGVBQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsQ0FBQSxDQUFBLE9BQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxlQUFBLEdBQUEsVUFBQSxVQUFBLEVBQUE7Ozs7Ozs7Ozs7QUFVQSxnQkFBQSxJQUFBLENBQUEsZUFBQSxFQUFBLElBQUEsVUFBQSxLQUFBLElBQUEsRUFBQTtBQUNBLHVCQUFBLEVBQUEsQ0FBQSxJQUFBLENBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxDQUFBO2FBQ0E7Ozs7O0FBS0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxVQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsaUJBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLElBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUVBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEtBQUEsR0FBQSxVQUFBLFdBQUEsRUFBQTtBQUNBLG1CQUFBLEtBQUEsQ0FBQSxJQUFBLENBQUEsUUFBQSxFQUFBLFdBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxpQkFBQSxDQUFBLFNBQ0EsQ0FBQSxZQUFBO0FBQ0EsdUJBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxFQUFBLE9BQUEsRUFBQSw0QkFBQSxFQUFBLENBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsbUJBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxTQUFBLENBQUEsQ0FBQSxJQUFBLENBQUEsWUFBQTtBQUNBLHVCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7QUFDQSwwQkFBQSxDQUFBLFVBQUEsQ0FBQSxXQUFBLENBQUEsYUFBQSxDQUFBLENBQUE7YUFDQSxDQUFBLENBQUE7U0FDQSxDQUFBOztBQUVBLFlBQUEsQ0FBQSxNQUFBLEdBQUEsVUFBQSxXQUFBLEVBQUE7QUFDQSxtQkFBQSxLQUFBLENBQUEsSUFBQSxDQUFBLFNBQUEsRUFBQSxXQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsa0JBQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQTtLQUdBLENBQUEsQ0FBQTs7QUFFQSxPQUFBLENBQUEsT0FBQSxDQUFBLFNBQUEsRUFBQSxVQUFBLFVBQUEsRUFBQSxXQUFBLEVBQUE7O0FBRUEsWUFBQSxJQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxnQkFBQSxFQUFBLFlBQUE7QUFDQSxnQkFBQSxDQUFBLE9BQUEsRUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBOztBQUVBLGtCQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxjQUFBLEVBQUEsWUFBQTtBQUNBLGdCQUFBLENBQUEsT0FBQSxFQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7O0FBRUEsWUFBQSxDQUFBLEVBQUEsR0FBQSxJQUFBLENBQUE7QUFDQSxZQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxZQUFBLENBQUEsTUFBQSxHQUFBLFVBQUEsU0FBQSxFQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLENBQUEsRUFBQSxHQUFBLFNBQUEsQ0FBQTtBQUNBLGdCQUFBLENBQUEsSUFBQSxHQUFBLElBQUEsQ0FBQTtTQUNBLENBQUE7O0FBRUEsWUFBQSxDQUFBLE9BQUEsR0FBQSxZQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxFQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsZ0JBQUEsQ0FBQSxJQUFBLEdBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQTtLQUVBLENBQUEsQ0FBQTtDQUVBLENBQUEsRUFBQSxDQUFBOztBQ3BKQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLENBQUEsTUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLEdBQUE7QUFDQSxtQkFBQSxFQUFBLG1CQUFBO0FBQ0Esa0JBQUEsRUFBQSxvQkFBQSxNQUFBLEVBQUEs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TUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsVUFBQSxDQUFBLEtBQUEsR0FBQSxFQUFBLENBQUE7QUFDQSxVQUFBLENBQUEsS0FBQSxHQUFBLElBQUEsQ0FBQTs7QUFFQSxVQUFBLENBQUEsU0FBQSxHQUFBLFVBQUEsU0FBQSxFQUFBOztBQUVBLGNBQUEsQ0FBQSxLQUFBLEdBQUEsSUFBQSxDQUFBOztBQUVBLG1CQUFBLENBQUEsS0FBQSxDQUFBLFNBQUEsQ0FBQSxDQUFBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLGdCQUFBLElBQUEsQ0FBQSxPQUFBLEVBQUEsTUFBQSxDQUFBLEVBQUEsQ0FBQSxXQUFBLEVBQUEsRUFBQSxRQUFBLEVBQUEsSUFBQSxDQUFBLEdBQUEsRUFBQSxDQUFBLENBQUEsS0FDQSxNQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO1NBQ0EsQ0FBQSxTQUFBLENBQUEsWUFBQTtBQUNBLGtCQUFBLENBQUEsS0FBQSxHQUFBLDRCQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ3hCQSxHQUFBLENBQUEsTUFBQSxDQUFBLFVBQUEsY0FBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FDQSxLQUFBLENBQUEsV0FBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLGdCQUFBO0FBQ0EsbUJBQUEsRUFBQSw2QkFBQTtBQUNBLGtCQUFBLEVBQUEsV0FBQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUFFQSxHQUFBLENBQUEsVUFBQSxDQUFBLFdBQUEsRUFBQSxVQUFBLE1BQUEsRUFBQSxXQUFBLEVBQUEsWUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxVQUFBLE9BQUEsRUFBQTtBQUNBLG1CQUFBLENBQUEsSUFBQSxDQUFBLFlBQUEsQ0FBQSxNQUFBLEVBQUEsRUFBQSxTQUFBLEVBQUEsS0FBQSxFQUFBLFVBQUEsRUFBQSxPQUFBLEVBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLHVCQUFBLENBQUEsS0FBQSxDQUFBLEVBQUEsS0FBQSxFQUFBLElBQUEsQ0FBQSxLQUFBLEVBQUEsUUFBQSxFQUFBLE9BQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7QUFDQSxzQkFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTthQUNBLENBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDcEJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7O0FBRUEsa0JBQUEsQ0FBQSxLQUFBLENBQUEsUUFBQSxFQUFBO0FBQ0EsV0FBQSxFQUFBLFNBQUE7QUFDQSxtQkFBQSxFQUFBLHVCQUFBO0FBQ0Esa0JBQUEsRUFBQSxZQUFBO0tBQ0EsQ0FBQSxDQUFBO0NBRUEsQ0FBQSxDQUFBOztBQUVBLEdBQUEsQ0FBQSxVQUFBLENBQUEsWUFBQSxFQUFBLFVBQUEsTUFBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsVUFBQSxDQUFBLEtBQUEsR0FBQSxJQUFBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFVBQUEsR0FBQSxVQUFBLFVBQUEsRUFBQTtBQUNBLGNBQUEsQ0FBQSxLQUFBLEdBQUEsSUFBQSxDQUFBO0FBQ0EsbUJBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFlBQUE7QUFDQSxrQkFBQSxDQUFBLEVBQUEsQ0FBQSxNQUFBLENBQUEsQ0FBQTtTQUNBLENBQUEsU0FDQSxDQUFBLFlBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsR0FBQSxpQkFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBRUEsQ0FBQTtDQUVBLENBQUEsQ0FBQTs7QUMxQkEsR0FBQSxDQUFBLE1BQUEsQ0FBQSxVQUFBLGNBQUEsRUFBQTtBQUNBLGtCQUFBLENBQ0EsS0FBQSxDQUFBLE1BQUEsRUFBQTtBQUNBLFdBQUEsRUFBQSxlQUFBO0FBQ0EsbUJBQUEsRUFBQSxvQkFBQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLFFBQUEsRUFBQTtBQUNBLGtCQUFBLENBQUEsSUFBQSxHQUFBLFFBQUEsQ0FBQTtTQUNBO0FBQ0EsZUFBQSxFQUFBO0FBQ0Esb0JBQUEsRUFBQSxrQkFBQSxZQUFBLEVBQUEsV0FBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxDQUFBLE9BQUEsQ0FBQSxZQUFBLENBQUEsTUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsSUFBQSxFQUFBO0FBQ0EsMkJBQUEsSUFBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBO1NBQ0E7S0FDQSxDQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDakJBLEdBQUEsQ0FBQSxNQUFBLENBQUEsVUFBQSxjQUFBLEVBQUE7QUFDQSxrQkFBQSxDQUFBLEtBQUEsQ0FBQSxPQUFBLEVBQUE7QUFDQSxXQUFBLEVBQUEsUUFBQTtBQUNBLG1CQUFBLEVBQUEsc0JBQUE7QUFDQSxlQUFBLEVBQUE7QUFDQSxpQkFBQSxFQUFBLGVBQUEsV0FBQSxFQUFBO0FBQ0EsdUJBQUEsV0FBQSxDQUFBLE1BQUEsRUFBQSxDQUFBO2FBQ0E7U0FDQTtBQUNBLGtCQUFBLEVBQUEsb0JBQUEsTUFBQSxFQUFBLEtBQUEsRUFBQSxPQUFBLEVBQUEsTUFBQSxFQUFBO0FBQ0Esa0JBQUEsQ0FBQSxLQUFBLEdBQUEsS0FBQSxDQUFBOzs7Ozs7U0FNQTtLQUNBLENBQUEsQ0FBQTtDQUNBLENBQUEsQ0FBQTs7QUNsQkEsR0FBQSxDQUFBLE9BQUEsQ0FBQSxjQUFBLEVBQUEsVUFBQSxLQUFBLEVBQUE7QUFDQSxRQUFBLE1BQUEsR0FBQSxTQUFBLE1BQUEsQ0FBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLENBQUEsTUFBQSxDQUFBLElBQUEsRUFBQSxLQUFBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLE1BQUEsR0FBQSxZQUFBO0FBQ0EsZUFBQSxLQUFBLENBQUEsR0FBQSxDQUFBLFdBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUVBLFVBQUEsQ0FBQSxTQUFBLEdBQUEsWUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxrQkFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsVUFBQSxDQUFBLFNBQUEsR0FBQSxVQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLElBQUEsQ0FBQSxhQUFBLEVBQUEsS0FBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsV0FBQSxNQUFBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDM0JBLEdBQUEsQ0FBQSxPQUFBLENBQUEsYUFBQSxFQUFBLFVBQUEsS0FBQSxFQUFBOztBQUVBLFFBQUEsSUFBQSxHQUFBLFNBQUEsSUFBQSxDQUFBLEtBQUEsRUFBQTtBQUNBLGVBQUEsQ0FBQSxNQUFBLENBQUEsSUFBQSxFQUFBLEtBQUEsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLENBQUEsTUFBQSxHQUFBLFlBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsWUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsUUFBQSxDQUFBLE9BQUEsR0FBQSxVQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxDQUFBLEdBQUEsQ0FBQSxhQUFBLEdBQUEsRUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsUUFBQSxFQUFBO0FBQ0EsbUJBQUEsUUFBQSxDQUFBLElBQUEsQ0FBQTtTQUNBLENBQUEsQ0FBQTtLQUNBLENBQUE7O0FBRUEsUUFBQSxDQUFBLElBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQSxLQUFBLEVBQUE7QUFDQSxlQUFBLEtBQUEsQ0FBQSxHQUFBLENBQUEsYUFBQSxHQUFBLEVBQUEsRUFBQSxLQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsVUFBQSxRQUFBLEVBQUE7QUFDQSxtQkFBQSxRQUFBLENBQUEsSUFBQSxDQUFBO1NBQ0EsQ0FBQSxDQUFBO0tBQ0EsQ0FBQTs7QUFFQSxRQUFBLFVBQUEsR0FBQSxVQUFBLEVBQUEsRUFBQTtBQUNBLGVBQUEsS0FBQSxVQUFBLENBQUEsYUFBQSxHQUFBLEVBQUEsQ0FBQSxDQUNBLElBQUEsQ0FBQSxVQUFBLFFBQUEsRUFBQTtBQUNBLG1CQUFBLFFBQUEsQ0FBQSxJQUFBLENBQUE7U0FDQSxDQUFBLENBQUE7S0FDQSxDQUFBOztBQUdBLFdBQUEsSUFBQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ3BDQSxHQUFBLENBQUEsU0FBQSxDQUFBLFdBQUEsRUFBQSxZQUFBO0FBQ0EsV0FBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtBQUNBLG1CQUFBLEVBQUEsNkNBQUE7S0FDQSxDQUFBO0NBQ0EsQ0FBQSxDQUFBOztBQ0xBLEdBQUEsQ0FBQSxTQUFBLENBQUEsWUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxJQUFBO0FBQ0EsbUJBQUEsRUFBQSxtREFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDTEEsR0FBQSxDQUFBLFNBQUEsQ0FBQSxRQUFBLEVBQUEsVUFBQSxVQUFBLEVBQUEsV0FBQSxFQUFBLFdBQUEsRUFBQSxNQUFBLEVBQUE7O0FBRUEsV0FBQTtBQUNBLGdCQUFBLEVBQUEsR0FBQTtBQUNBLGFBQUEsRUFBQSxFQUFBO0FBQ0EsbUJBQUEsRUFBQSx5Q0FBQTtBQUNBLFlBQUEsRUFBQSxjQUFBLEtBQUEsRUFBQTs7QUFFQSxpQkFBQSxDQUFBLEtBQUEsR0FBQSxDQUNBLEVBQUEsS0FBQSxFQUFBLFFBQUEs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QUFBLENBQUEsQ0FBQTtBQUNBLHFCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLHFCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTthQUNBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFFBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLDJCQUFBLENBQUEsSUFBQSxDQUFBLElBQUEsQ0FBQSxHQUFBLEVBQUEsSUFBQSxDQUFBLENBQ0EsSUFBQSxDQUFBLFVBQUEsV0FBQSxFQUFBO0FBQ0EseUJBQUEsQ0FBQSxJQUFBLEdBQUEsV0FBQSxDQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO0FBQ0EseUJBQUEsQ0FBQSxRQUFBLEdBQUEsS0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBLENBQUE7QUFDQSxpQkFBQSxDQUFBLFVBQUEsR0FBQSxVQUFBLElBQUEsRUFBQTtBQUNBLDJCQUFBLFVBQUEsQ0FBQSxJQUFBLENBQUEsQ0FDQSxJQUFBLENBQUEsWUFBQTtBQUNBLHlCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLHlCQUFBLENBQUEsUUFBQSxHQUFBLEtBQUEsQ0FBQTtBQUNBLDBCQUFBLENBQUEsRUFBQSxDQUFBLE1BQUEsQ0FBQSxDQUFBO2lCQUNBLENBQUEsQ0FBQTthQUNBLENBQUE7O0FBRUEsaUJBQUEsQ0FBQSxZQUFBLEdBQUEsWUFBQTs7Ozs7O0FBTUEscUJBQUEsQ0FBQSxNQUFBLEdBQUEsT0FBQSxDQUFBLElBQUEsQ0FBQSxLQUFBLENBQUEsSUFBQSxDQUFBLENBQUE7QUFDQSxxQkFBQSxDQUFBLFFBQUEsR0FBQSxJQUFBLENBQUE7YUFDQSxDQUFBO1NBQ0E7QUFDQSxhQUFBLEVBQUE7QUFDQSxnQkFBQSxFQUFBLEdBQUE7U0FDQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUE7O0FDckRBLEdBQUEsQ0FBQSxTQUFBLENBQUEsVUFBQSxFQUFBLFlBQUE7QUFDQSxXQUFBO0FBQ0EsZ0JBQUEsRUFBQSxHQUFBO0FBQ0EsbUJBQUEsRUFBQSxxREFBQTtLQUNBLENBQUE7Q0FDQSxDQUFBLENBQUEiLCJmaWxlIjoibWFpbi5qcyIsInNvdXJjZXNDb250ZW50IjpbIid1c2Ugc3RyaWN0JztcbndpbmRvdy5hcHAgPSBhbmd1bGFyLm1vZHVsZSgnTVNGVGVtcCcsIFsndWkucm91dGVyJywgJ3VpLmJvb3RzdHJhcCcsICdmc2FQcmVCdWlsdCddKTtcblxuYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHVybFJvdXRlclByb3ZpZGVyLCAkbG9jYXRpb25Qcm92aWRlcikge1xuXG5cdC8vIHRoaXMgbWFrZXMgdGhlICcvdXNlcnMvJyByb3V0ZSBjb3JyZWN0bHkgcmVkaXJlY3QgdG8gJy91c2Vycydcblx0JHVybFJvdXRlclByb3ZpZGVyLnJ1bGUoZnVuY3Rpb24gKCRpbmplY3RvciwgJGxvY2F0aW9uKSB7XG5cblx0XHR2YXIgcmUgPSAvKC4rKShcXC8rKShcXD8uKik/JC9cblx0XHR2YXIgcGF0aCA9ICRsb2NhdGlvbi51cmwoKTtcblxuXHRcdGlmKHJlLnRlc3QocGF0aCkpIHtcblx0XHRcdHJldHVybiBwYXRoLnJlcGxhY2UocmUsICckMSQzJylcblx0XHR9XG5cblx0XHRyZXR1cm4gZmFsc2U7XG5cdH0pO1xuXHQvLyBUaGlzIHR1cm5zIG9mZiBoYXNoYmFuZyB1cmxzICgvI2Fib3V0KSBhbmQgY2hhbmdlcyBpdCB0byBzb21ldGhpbmcgbm9ybWFsICgvYWJvdXQpXG5cdCRsb2NhdGlvblByb3ZpZGVyLmh0bWw1TW9kZSh0cnVlKTtcblx0JHVybFJvdXRlclByb3ZpZGVyLndoZW4oJy9hdXRoLzpwcm92aWRlcicsIGZ1bmN0aW9uICgpIHtcblx0XHR3aW5kb3cubG9jYXRpb24ucmVsb2FkKCk7XG5cdH0pO1xuXHQvLyBJZiB3ZSBnbyB0byBhIFVSTCB0aGF0IHVpLXJvdXRlciBkb2Vzbid0IGhhdmUgcmVnaXN0ZXJlZCwgZ28gdG8gdGhlIFwiL1wiIHVybC5cblx0JHVybFJvdXRlclByb3ZpZGVyLm90aGVyd2lzZSgnLycpO1xuXG59KTtcblxuLy8gVGhpcyBhcHAucnVuIGlzIGZvciBjb250cm9sbGluZyBhY2Nlc3MgdG8gc3BlY2lmaWMgc3RhdGVzLlxuYXBwLnJ1bihmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG5cdC8vIFRoZSBnaXZlbiBzdGF0ZSByZXF1aXJlcyBhbiBhdXRoZW50aWNhdGVkIHVzZXIuXG5cdHZhciBkZXN0aW5hdGlvblN0YXRlUmVxdWlyZXNBdXRoID0gZnVuY3Rpb24gKHN0YXRlKSB7XG5cdFx0cmV0dXJuIHN0YXRlLmRhdGEgJiYgc3RhdGUuZGF0YS5hdXRoZW50aWNhdGU7XG5cdH07XG5cblx0Ly8gJHN0YXRlQ2hhbmdlU3RhcnQgaXMgYW4gZXZlbnQgZmlyZWRcblx0Ly8gd2hlbmV2ZXIgdGhlIHByb2Nlc3Mgb2YgY2hhbmdpbmcgYSBzdGF0ZSBiZWdpbnMuXG5cdCRyb290U2NvcGUuJG9uKCckc3RhdGVDaGFuZ2VTdGFydCcsIGZ1bmN0aW9uIChldmVudCwgdG9TdGF0ZSwgdG9QYXJhbXMpIHtcblxuXHRcdGlmICghZGVzdGluYXRpb25TdGF0ZVJlcXVpcmVzQXV0aCh0b1N0YXRlKSkge1xuXHRcdFx0Ly8gVGhlIGRlc3RpbmF0aW9uIHN0YXRlIGRvZXMgbm90IHJlcXVpcmUgYXV0aGVudGljYXRpb25cblx0XHRcdC8vIFNob3J0IGNpcmN1aXQgd2l0aCByZXR1cm4uXG5cdFx0XHRyZXR1cm47XG5cdFx0fVxuXG5cdFx0aWYgKEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpKSB7XG5cdFx0XHQvLyBUaGUgdXNlciBpcyBhdXRoZW50aWNhdGVkLlxuXHRcdFx0Ly8gU2hvcnQgY2lyY3VpdCB3aXRoIHJldHVybi5cblx0XHRcdHJldHVybjtcblx0XHR9XG5cblx0XHQvLyBDYW5jZWwgbmF2aWdhdGluZyB0byBuZXcgc3RhdGUuXG5cdFx0ZXZlbnQucHJldmVudERlZmF1bHQoKTtcblxuXHRcdEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcblx0XHRcdC8vIElmIGEgdXNlciBpcyByZXRyaWV2ZWQsIHRoZW4gcmVuYXZpZ2F0ZSB0byB0aGUgZGVzdGluYXRpb25cblx0XHRcdC8vICh0aGUgc2Vjb25kIHRpbWUsIEF1dGhTZXJ2aWNlLmlzQXV0aGVudGljYXRlZCgpIHdpbGwgd29yaylcblx0XHRcdC8vIG90aGVyd2lzZSwgaWYgbm8gdXNlciBpcyBsb2dnZWQgaW4sIGdvIHRvIFwibG9naW5cIiBzdGF0ZS5cblx0XHRcdGlmICh1c2VyKSB7XG5cdFx0XHRcdCRzdGF0ZS5nbyh0b1N0YXRlLm5hbWUsIHRvUGFyYW1zKTtcblx0XHRcdH0gZWxzZSB7XG5cdFx0XHRcdCRzdGF0ZS5nbygnbG9naW4nKTtcblx0XHRcdH1cblx0XHR9KTtcblxuXHR9KTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdhbGVydHMnLCB7XG4gICAgICAgIHVybDogJy9hbGVydHMnLFxuICAgICAgICB0ZW1wbGF0ZVVybDogJ2pzL2FsZXJ0cy9hbGVydHMuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6ICdhbGVydEN0cmwnXG4gICAgfSlcbn0pXG5cbmFwcC5jb250cm9sbGVyKCdhbGVydEN0cmwnLCBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5LCAkc2NvcGUsICRzdGF0ZSkge1xuICAgICRzY29wZS5zZW5kQWxlcnQgPSBmdW5jdGlvbiAoYWxlcnQpIHtcbiAgICAgICAgRHdlZXRGYWN0b3J5LnBvc3RBbGVydChhbGVydClcbiAgICAgICAgLnRoZW4gKGZ1bmN0aW9uIChwb3N0ZWRBbGVydCkge1xuICAgICAgICAgICAgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgICAgIH0pXG4gICAgfVxufSlcbiIsImFwcC5jb25maWcoZnVuY3Rpb24gKCRzdGF0ZVByb3ZpZGVyKSB7XG4gICAgJHN0YXRlUHJvdmlkZXJcbiAgICAuc3RhdGUoJ2RhdGEnLCB7XG4gICAgICAgIHVybDogJy9kYXRhJyxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9kYXRhL2RhdGEuaHRtbCcsXG4gICAgICAgIGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIGFsbER3ZWV0cykge1xuICAgICAgICAgICRzY29wZS5kd2VldHMgPSBhbGxEd2VldHM7XG4gICAgICAgIH0sXG4gICAgICAgIHJlc29sdmU6IHtcbiAgICAgICAgICAgIC8vIGZpbmREd2VldHM6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgIC8vICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldEFsbCgpO1xuICAgICAgICAgICAgLy8gfTtcbiAgICAgICAgICAgIGFsbER3ZWV0czogZnVuY3Rpb24gKER3ZWV0RmFjdG9yeSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBEd2VldEZhY3RvcnkuZ2V0QWxsKCk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KVxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdkb2NzJywge1xuICAgICAgICB1cmw6ICcvZG9jcycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvZG9jcy9kb2NzLmh0bWwnXG4gICAgfSk7XG59KTtcbiIsIihmdW5jdGlvbiAoKSB7XG5cbiAgICAndXNlIHN0cmljdCc7XG5cbiAgICAvLyBIb3BlIHlvdSBkaWRuJ3QgZm9yZ2V0IEFuZ3VsYXIhIER1aC1kb3kuXG4gICAgaWYgKCF3aW5kb3cuYW5ndWxhcikgdGhyb3cgbmV3IEVycm9yKCdJIGNhblxcJ3QgZmluZCBBbmd1bGFyIScpO1xuXG4gICAgdmFyIGFwcCA9IGFuZ3VsYXIubW9kdWxlKCdmc2FQcmVCdWlsdCcsIFtdKTtcblxuICAgIGFwcC5mYWN0b3J5KCdTb2NrZXQnLCBmdW5jdGlvbiAoKSB7XG4gICAgICAgIGlmICghd2luZG93LmlvKSB0aHJvdyBuZXcgRXJyb3IoJ3NvY2tldC5pbyBub3QgZm91bmQhJyk7XG4gICAgICAgIHJldHVybiB3aW5kb3cuaW8od2luZG93LmxvY2F0aW9uLm9yaWdpbik7XG4gICAgfSk7XG5cbiAgICAvLyBBVVRIX0VWRU5UUyBpcyB1c2VkIHRocm91Z2hvdXQgb3VyIGFwcCB0b1xuICAgIC8vIGJyb2FkY2FzdCBhbmQgbGlzdGVuIGZyb20gYW5kIHRvIHRoZSAkcm9vdFNjb3BlXG4gICAgLy8gZm9yIGltcG9ydGFudCBldmVudHMgYWJvdXQgYXV0aGVudGljYXRpb24gZmxvdy5cbiAgICBhcHAuY29uc3RhbnQoJ0FVVEhfRVZFTlRTJywge1xuICAgICAgICBsb2dpblN1Y2Nlc3M6ICdhdXRoLWxvZ2luLXN1Y2Nlc3MnLFxuICAgICAgICBsb2dpbkZhaWxlZDogJ2F1dGgtbG9naW4tZmFpbGVkJyxcbiAgICAgICAgc2lnbnVwU3VjY2VzczogJ2F1dGgtc2lnbnVwLXN1Y2Nlc3MnLFxuICAgICAgICBzaWdudXBGYWlsZWQ6ICdhdXRoLXNpZ251cC1mYWlsZWQnLFxuICAgICAgICBsb2dvdXRTdWNjZXNzOiAnYXV0aC1sb2dvdXQtc3VjY2VzcycsXG4gICAgICAgIHNlc3Npb25UaW1lb3V0OiAnYXV0aC1zZXNzaW9uLXRpbWVvdXQnLFxuICAgICAgICBub3RBdXRoZW50aWNhdGVkOiAnYXV0aC1ub3QtYXV0aGVudGljYXRlZCcsXG4gICAgICAgIG5vdEF1dGhvcml6ZWQ6ICdhdXRoLW5vdC1hdXRob3JpemVkJ1xuICAgIH0pO1xuXG4gICAgYXBwLmZhY3RvcnkoJ0F1dGhJbnRlcmNlcHRvcicsIGZ1bmN0aW9uICgkcm9vdFNjb3BlLCAkcSwgQVVUSF9FVkVOVFMpIHtcbiAgICAgICAgdmFyIHN0YXR1c0RpY3QgPSB7XG4gICAgICAgICAgICA0MDE6IEFVVEhfRVZFTlRTLm5vdEF1dGhlbnRpY2F0ZWQsXG4gICAgICAgICAgICA0MDM6IEFVVEhfRVZFTlRTLm5vdEF1dGhvcml6ZWQsXG4gICAgICAgICAgICA0MTk6IEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LFxuICAgICAgICAgICAgNDQwOiBBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dFxuICAgICAgICB9O1xuICAgICAgICByZXR1cm4ge1xuICAgICAgICAgICAgcmVzcG9uc2VFcnJvcjogZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICAgICAgJHJvb3RTY29wZS4kYnJvYWRjYXN0KHN0YXR1c0RpY3RbcmVzcG9uc2Uuc3RhdHVzXSwgcmVzcG9uc2UpO1xuICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QocmVzcG9uc2UpXG4gICAgICAgICAgICB9XG4gICAgICAgIH07XG4gICAgfSk7XG5cbiAgICBhcHAuY29uZmlnKGZ1bmN0aW9uICgkaHR0cFByb3ZpZGVyKSB7XG4gICAgICAgICRodHRwUHJvdmlkZXIuaW50ZXJjZXB0b3JzLnB1c2goW1xuICAgICAgICAgICAgJyRpbmplY3RvcicsXG4gICAgICAgICAgICBmdW5jdGlvbiAoJGluamVjdG9yKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuICRpbmplY3Rvci5nZXQoJ0F1dGhJbnRlcmNlcHRvcicpO1xuICAgICAgICAgICAgfVxuICAgICAgICBdKTtcbiAgICB9KTtcblxuICAgIGFwcC5zZXJ2aWNlKCdBdXRoU2VydmljZScsIGZ1bmN0aW9uICgkaHR0cCwgU2Vzc2lvbiwgJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMsICRxKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gb25TdWNjZXNzZnVsTG9naW4ocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzKTtcbiAgICAgICAgICAgIHJldHVybiBkYXRhLnVzZXI7XG4gICAgICAgIH1cblxuICAgICAgICAvL2FkZCBzdWNjZXNzZnVsIHNpZ251cFxuICAgICAgICBmdW5jdGlvbiBvblN1Y2Nlc3NmdWxTaWdudXAocmVzcG9uc2UpIHtcbiAgICAgICAgICAgIHZhciBkYXRhID0gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgICAgIFNlc3Npb24uY3JlYXRlKGRhdGEuaWQsIGRhdGEudXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRicm9hZGNhc3QoQVVUSF9FVkVOVFMuc2lnbnVwU3VjY2Vzcyk7XG4gICAgICAgICAgICByZXR1cm4gZGF0YS51c2VyO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gVXNlcyB0aGUgc2Vzc2lvbiBmYWN0b3J5IHRvIHNlZSBpZiBhblxuICAgICAgICAvLyBhdXRoZW50aWNhdGVkIHVzZXIgaXMgY3VycmVudGx5IHJlZ2lzdGVyZWQuXG4gICAgICAgIHRoaXMuaXNBdXRoZW50aWNhdGVkID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICEhU2Vzc2lvbi51c2VyO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuZ2V0TG9nZ2VkSW5Vc2VyID0gZnVuY3Rpb24gKGZyb21TZXJ2ZXIpIHtcblxuICAgICAgICAgICAgLy8gSWYgYW4gYXV0aGVudGljYXRlZCBzZXNzaW9uIGV4aXN0cywgd2VcbiAgICAgICAgICAgIC8vIHJldHVybiB0aGUgdXNlciBhdHRhY2hlZCB0byB0aGF0IHNlc3Npb25cbiAgICAgICAgICAgIC8vIHdpdGggYSBwcm9taXNlLiBUaGlzIGVuc3VyZXMgdGhhdCB3ZSBjYW5cbiAgICAgICAgICAgIC8vIGFsd2F5cyBpbnRlcmZhY2Ugd2l0aCB0aGlzIG1ldGhvZCBhc3luY2hyb25vdXNseS5cblxuICAgICAgICAgICAgLy8gT3B0aW9uYWxseSwgaWYgdHJ1ZSBpcyBnaXZlbiBhcyB0aGUgZnJvbVNlcnZlciBwYXJhbWV0ZXIsXG4gICAgICAgICAgICAvLyB0aGVuIHRoaXMgY2FjaGVkIHZhbHVlIHdpbGwgbm90IGJlIHVzZWQuXG5cbiAgICAgICAgICAgIGlmICh0aGlzLmlzQXV0aGVudGljYXRlZCgpICYmIGZyb21TZXJ2ZXIgIT09IHRydWUpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gJHEud2hlbihTZXNzaW9uLnVzZXIpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBNYWtlIHJlcXVlc3QgR0VUIC9zZXNzaW9uLlxuICAgICAgICAgICAgLy8gSWYgaXQgcmV0dXJucyBhIHVzZXIsIGNhbGwgb25TdWNjZXNzZnVsTG9naW4gd2l0aCB0aGUgcmVzcG9uc2UuXG4gICAgICAgICAgICAvLyBJZiBpdCByZXR1cm5zIGEgNDAxIHJlc3BvbnNlLCB3ZSBjYXRjaCBpdCBhbmQgaW5zdGVhZCByZXNvbHZlIHRvIG51bGwuXG4gICAgICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvc2Vzc2lvbicpLnRoZW4ob25TdWNjZXNzZnVsTG9naW4pLmNhdGNoKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgIH07XG5cbiAgICAgICAgdGhpcy5sb2dpbiA9IGZ1bmN0aW9uIChjcmVkZW50aWFscykge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9sb2dpbicsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bExvZ2luKVxuICAgICAgICAgICAgICAgIC5jYXRjaChmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiAkcS5yZWplY3QoeyBtZXNzYWdlOiAnSW52YWxpZCBsb2dpbiBjcmVkZW50aWFscy4nIH0pO1xuICAgICAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMubG9nb3V0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgcmV0dXJuICRodHRwLmdldCgnL2xvZ291dCcpLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIFNlc3Npb24uZGVzdHJveSgpO1xuICAgICAgICAgICAgICAgICRyb290U2NvcGUuJGJyb2FkY2FzdChBVVRIX0VWRU5UUy5sb2dvdXRTdWNjZXNzKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9O1xuXG4gICAgICAgIHRoaXMuc2lnbnVwID0gZnVuY3Rpb24gKGNyZWRlbnRpYWxzKSB7XG4gICAgICAgICAgICByZXR1cm4gJGh0dHAucG9zdCgnL3NpZ251cCcsIGNyZWRlbnRpYWxzKVxuICAgICAgICAgICAgICAgIC50aGVuKG9uU3VjY2Vzc2Z1bFNpZ251cCk7XG4gICAgICAgIH07XG5cblxuICAgIH0pO1xuXG4gICAgYXBwLnNlcnZpY2UoJ1Nlc3Npb24nLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQVVUSF9FVkVOVFMpIHtcblxuICAgICAgICB2YXIgc2VsZiA9IHRoaXM7XG5cbiAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubm90QXV0aGVudGljYXRlZCwgZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgc2VsZi5kZXN0cm95KCk7XG4gICAgICAgIH0pO1xuXG4gICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNlc3Npb25UaW1lb3V0LCBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICBzZWxmLmRlc3Ryb3koKTtcbiAgICAgICAgfSk7XG5cbiAgICAgICAgdGhpcy5pZCA9IG51bGw7XG4gICAgICAgIHRoaXMudXNlciA9IG51bGw7XG5cbiAgICAgICAgdGhpcy5jcmVhdGUgPSBmdW5jdGlvbiAoc2Vzc2lvbklkLCB1c2VyKSB7XG4gICAgICAgICAgICB0aGlzLmlkID0gc2Vzc2lvbklkO1xuICAgICAgICAgICAgdGhpcy51c2VyID0gdXNlcjtcbiAgICAgICAgfTtcblxuICAgICAgICB0aGlzLmRlc3Ryb3kgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICB0aGlzLmlkID0gbnVsbDtcbiAgICAgICAgICAgIHRoaXMudXNlciA9IG51bGw7XG4gICAgICAgIH07XG5cbiAgICB9KTtcblxufSkoKTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnaG9tZScsIHtcbiAgICAgICAgdXJsOiAnLycsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvaG9tZS9ob21lLmh0bWwnLFxuICAgICAgICBjb250cm9sbGVyOiBmdW5jdGlvbigkc2NvcGUsIER3ZWV0RmFjdG9yeSwgbGF0ZXN0VGVtcCkge1xuICAgICAgICAgICAgLy9DcmVhdGUgYXJyYXkgb2YgbGF0ZXN0IGR3ZWV0cyB0byBkaXNwbGF5IG9uIGhvbWUgc3RhdGVcbiAgICAgICAgICAgICRzY29wZS5ob21lRHdlZXRzID0gW107XG5cbiAgICAgICAgICAgIC8vSW5pdGlhbGl6ZSB3aXRoIGZpcnN0IGR3ZWV0XG4gICAgICAgICAgICBEd2VldEZhY3RvcnkuZ2V0TGF0ZXN0KClcbiAgICAgICAgICAgIC50aGVuKGZ1bmN0aW9uKGR3ZWV0KXtcbiAgICAgICAgICAgICAgICAkc2NvcGUucHJldkR3ZWV0ID0gZHdlZXQ7XG4gICAgICAgICAgICB9KTtcblxuICAgICAgICAgICAgdmFyIGxpbmUxID0gbmV3IFRpbWVTZXJpZXMoKTtcbiAgICAgICAgICAgIHZhciBsaW5lMiA9IG5ldyBUaW1lU2VyaWVzKCk7XG5cbiAgICAgICAgICAgIC8vQ2hlY2sgZXZlcnkgaGFsZiBzZWNvbmQgdG8gc2VlIGlmIHRoZSBsYXN0IGR3ZWV0IGlzIG5ldywgdGhlbiBwdXNoIHRvIGhvbWVEd2VldHMsIHRoZW4gcGxvdFxuICAgICAgICAgICAgLy8gc2V0SW50ZXJ2YWwoZnVuY3Rpb24oKSB7XG4gICAgICAgICAgICAvLyAgICAgRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpXG4gICAgICAgICAgICAvLyAgICAgLnRoZW4oZnVuY3Rpb24oZHdlZXQpe1xuICAgICAgICAgICAgLy8gICAgICAgICAkc2NvcGUubGFzdER3ZWV0ID0gZHdlZXQ7XG4gICAgICAgICAgICAvLyAgICAgfSlcbiAgICAgICAgICAgIC8vICAgICAudGhlbihmdW5jdGlvbigpIHtcbiAgICAgICAgICAgIC8vICAgICAgICAgaWYgKCRzY29wZS5wcmV2RHdlZXQuY3JlYXRlZCAhPSAkc2NvcGUubGFzdER3ZWV0LmNyZWF0ZWQpIHtcbiAgICAgICAgICAgIC8vICAgICAgICAgICAgICRzY29wZS5ob21lRHdlZXRzLnB1c2goJHNjb3BlLmxhc3REd2VldCk7XG4gICAgICAgICAgICAvLyAgICAgICAgICAgICAkc2NvcGUucHJldkR3ZWV0ID0gJHNjb3BlLmxhc3REd2VldDtcbiAgICAgICAgICAgIC8vICAgICAgICAgICAgIGxpbmUxLmFwcGVuZChuZXcgRGF0ZSgpLmdldFRpbWUoKSwgJHNjb3BlLmxhc3REd2VldC5jb250ZW50WydUZW1wZXJhdHVyZSddKTtcbiAgICAgICAgICAgIC8vICAgICAgICAgICAgIC8vUmFuZG9tIHBsb3QgdG8gY2hlY2sgdGhhdCB0aGUgZ3JhcGggaXMgd29ya2luZ1xuICAgICAgICAgICAgLy8gICAgICAgICAgICAgbGluZTIuYXBwZW5kKG5ldyBEYXRlKCkuZ2V0VGltZSgpLCBNYXRoLmZsb29yKE1hdGgucmFuZG9tKCkqNCs3MCkpO1xuICAgICAgICAgICAgLy8gICAgICAgICB9XG4gICAgICAgICAgICAvLyAgICAgICAgIHdoaWxlKCRzY29wZS5ob21lRHdlZXRzLmxlbmd0aCA+IDEwMCkge1xuICAgICAgICAgICAgLy8gICAgICAgICAgICAgJHNjb3BlLmhvbWVEd2VldHMuc2hpZnQoKTtcbiAgICAgICAgICAgIC8vICAgICAgICAgfVxuICAgICAgICAgICAgLy8gICAgIH0pXG4gICAgICAgICAgICAvL1xuICAgICAgICAgICAgLy8gfSwgMTAwKTtcblxuXG4gICAgICAgICAgICAvL01ha2UgYSBzbW9vdGhpZSBjaGFydCB3aXRoIGFlc3RoZXRpY2FsbHkgcGxlYXNpbmcgcHJvcGVydGllc1xuICAgICAgICAgICAgdmFyIHNtb290aGllID0gbmV3IFNtb290aGllQ2hhcnQoe1xuICAgICAgICAgICAgICAgIGdyaWQ6IHtcbiAgICAgICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoNjMsIDE2MCwgMTgyKScsXG4gICAgICAgICAgICAgICAgICAgIGZpbGxTdHlsZTogJ3JnYig0LCA1LCA5MSknLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6IDEsXG4gICAgICAgICAgICAgICAgICAgIG1pbGxpc1BlckxpbmU6IDUwMCxcbiAgICAgICAgICAgICAgICAgICAgdmVydGljYWxTZWN0aW9uczogNFxuICAgICAgICAgICAgICAgIH0sXG4gICAgICAgICAgICAgICAgLy8gbWF4VmFsdWU6IDczLFxuICAgICAgICAgICAgICAgIC8vIG1pblZhbHVlOiA3MixcbiAgICAgICAgICAgICAgICBtYXhWYWx1ZVNjYWxlOiAxLjAxLFxuICAgICAgICAgICAgICAgIG1pblZhbHVlU2NhbGU6IDEuMDIsXG4gICAgICAgICAgICAgICAgdGltZXN0YW1wRm9ybWF0dGVyOlNtb290aGllQ2hhcnQudGltZUZvcm1hdHRlcixcbiAgICAgICAgICAgICAgICAvL1RoZSByYW5nZSBvZiBhY2NlcHRhYmxlIHRlbXBlcmF0dXJlcyB2aXN1YWxpemVkXG4gICAgICAgICAgICAgICAgLy9TaG91bGQgY2hhbmdlICd2YWx1ZScgYWNjb3JkaW5nbHlcbiAgICAgICAgICAgICAgICBob3Jpem9udGFsTGluZXM6W3tcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6JyM4ODAwMDAnLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6NSxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6bGF0ZXN0VGVtcCoxLjAwNSB8fCA3MFxuICAgICAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICAgICAgY29sb3I6JyM4ODAwMDAnLFxuICAgICAgICAgICAgICAgICAgICBsaW5lV2lkdGg6NSxcbiAgICAgICAgICAgICAgICAgICAgdmFsdWU6bGF0ZXN0VGVtcCowLjk5IHx8IDY4XG4gICAgICAgICAgICAgICAgfV1cbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBzbW9vdGhpZS5hZGRUaW1lU2VyaWVzKGxpbmUxLCB7XG4gICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoMCwgMjU1LCAwKScsXG4gICAgICAgICAgICAgICAgZmlsbFN0eWxlOiAncmdiYSgwLCAyNTUsIDAsIDAuNCknLFxuICAgICAgICAgICAgICAgIGxpbmVXaWR0aDogM1xuICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICBzbW9vdGhpZS5hZGRUaW1lU2VyaWVzKGxpbmUyLCB7XG4gICAgICAgICAgICAgICAgc3Ryb2tlU3R5bGU6ICdyZ2IoMjU1LCAwLCAyNTUpJyxcbiAgICAgICAgICAgICAgICBmaWxsU3R5bGU6ICdyZ2JhKDI1NSwgMCwgMjU1LCAwLjMpJyxcbiAgICAgICAgICAgICAgICBsaW5lV2lkdGg6IDNcbiAgICAgICAgICAgIH0pO1xuXG4gICAgICAgICAgICBzbW9vdGhpZS5zdHJlYW1Ubyhkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcImNoYXJ0XCIpLCAzMDApO1xuICAgICAgICB9LFxuICAgICAgICByZXNvbHZlOiB7XG4gICAgICAgICAgICBsYXRlc3RUZW1wOiBmdW5jdGlvbiAoRHdlZXRGYWN0b3J5KSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIER3ZWV0RmFjdG9yeS5nZXRMYXRlc3QoKVxuICAgICAgICAgICAgICAgIC50aGVuKCBmdW5jdGlvbiAoZHdlZXQpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGR3ZWV0LmNvbnRlbnRbJ1RlbXBlcmF0dXJlJ107XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9KTtcbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbigkc3RhdGVQcm92aWRlcikge1xuICAgICRzdGF0ZVByb3ZpZGVyLnN0YXRlKCdsYXRlc3QnLCB7XG4gICAgICAgIHVybDogJy9kYXRhL2xhdGVzdCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvbGF0ZXN0L2xhdGVzdC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogZnVuY3Rpb24gKCRzY29wZSwgbGF0ZXN0RHdlZXQpIHtcbiAgICAgICAgICAkc2NvcGUubGF0ZXN0RHdlZXQgPSBsYXRlc3REd2VldDtcbiAgICAgICAgfSxcbiAgICAgICAgcmVzb2x2ZToge1xuICAgICAgICAgICAgbGF0ZXN0RHdlZXQ6IGZ1bmN0aW9uIChEd2VldEZhY3RvcnkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gRHdlZXRGYWN0b3J5LmdldExhdGVzdCgpO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSlcbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuICAkc3RhdGVQcm92aWRlci5zdGF0ZSgnbG9naW4nLCB7XG4gICAgdXJsOiAnL2xvZ2luJyxcbiAgICB0ZW1wbGF0ZVVybDogJ2pzL2xvZ2luL2xvZ2luLmh0bWwnLFxuICAgIGNvbnRyb2xsZXI6ICdMb2dpbkN0cmwnXG4gIH0pO1xufSk7XG5cbmFwcC5jb250cm9sbGVyKCdMb2dpbkN0cmwnLCBmdW5jdGlvbiAoJHNjb3BlLCBBdXRoU2VydmljZSwgJHN0YXRlKSB7XG5cbiAgJHNjb3BlLmxvZ2luID0ge307XG4gICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgJHNjb3BlLnNlbmRMb2dpbiA9IGZ1bmN0aW9uIChsb2dpbkluZm8pIHtcblxuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICBBdXRoU2VydmljZS5sb2dpbihsb2dpbkluZm8pLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgaWYodXNlci5uZXdQYXNzKSAkc3RhdGUuZ28oJ3Jlc2V0UGFzcycsIHsndXNlcklkJzogdXNlci5faWR9KTtcbiAgICAgIGVsc2UgJHN0YXRlLmdvKCdob21lJyk7XG4gICAgfSkuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgJHNjb3BlLmVycm9yID0gJ0ludmFsaWQgbG9naW4gY3JlZGVudGlhbHMuJztcbiAgICB9KTtcbiAgfTtcbn0pO1xuIiwiYXBwLmNvbmZpZyhmdW5jdGlvbiAoJHN0YXRlUHJvdmlkZXIpIHtcbiAgICAkc3RhdGVQcm92aWRlclxuICAgIC5zdGF0ZSgncmVzZXRQYXNzJywge1xuICAgICAgICB1cmw6ICcvcmVzZXQvOnVzZXJJZCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvcmVzZXRQYXNzL3Jlc2V0UGFzcy5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1Jlc2V0Q3RybCdcbiAgICB9KTtcbn0pO1xuXG5hcHAuY29udHJvbGxlcignUmVzZXRDdHJsJywgZnVuY3Rpb24gKCRzY29wZSwgVXNlckZhY3RvcnksICRzdGF0ZVBhcmFtcywgQXV0aFNlcnZpY2UsICRzdGF0ZSkge1xuXG4gICAgJHNjb3BlLnJlc2V0UGFzcyA9IGZ1bmN0aW9uIChuZXdQYXNzKSB7XG4gICAgICAgIFVzZXJGYWN0b3J5LmVkaXQoJHN0YXRlUGFyYW1zLnVzZXJJZCwgeyduZXdQYXNzJzogZmFsc2UsICdwYXNzd29yZCc6IG5ld1Bhc3N9KVxuICAgICAgICAudGhlbiggZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmxvZ2luKHtlbWFpbDogdXNlci5lbWFpbCwgcGFzc3dvcmQ6IG5ld1Bhc3N9KVxuICAgICAgICAgICAgLnRoZW4oZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICAgICAgICAgIH0pO1xuICAgICAgICB9KVxuICAgIH1cbn0pXG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uICgkc3RhdGVQcm92aWRlcikge1xuXG4gICAgJHN0YXRlUHJvdmlkZXIuc3RhdGUoJ3NpZ251cCcsIHtcbiAgICAgICAgdXJsOiAnL3NpZ251cCcsXG4gICAgICAgIHRlbXBsYXRlVXJsOiAnanMvc2lnbnVwL3NpZ251cC5odG1sJyxcbiAgICAgICAgY29udHJvbGxlcjogJ1NpZ251cEN0cmwnXG4gICAgfSk7XG5cbn0pO1xuXG5hcHAuY29udHJvbGxlcignU2lnbnVwQ3RybCcsIGZ1bmN0aW9uICgkc2NvcGUsIEF1dGhTZXJ2aWNlLCAkc3RhdGUpIHtcblxuICAgICRzY29wZS5lcnJvciA9IG51bGw7XG5cbiAgICAkc2NvcGUuc2VuZFNpZ251cD0gZnVuY3Rpb24gKHNpZ251cEluZm8pIHtcbiAgICAgICAgJHNjb3BlLmVycm9yID0gbnVsbDtcbiAgICAgICAgQXV0aFNlcnZpY2Uuc2lnbnVwKHNpZ251cEluZm8pXG4gICAgICAgIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICRzdGF0ZS5nbygnaG9tZScpO1xuICAgICAgICB9KVxuICAgICAgICAuY2F0Y2goZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgJHNjb3BlLmVycm9yID0gJ0VtYWlsIGlzIHRha2VuISc7XG4gICAgICAgIH0pO1xuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuY29uZmlnKGZ1bmN0aW9uKCRzdGF0ZVByb3ZpZGVyKXtcbiAgJHN0YXRlUHJvdmlkZXJcbiAgLnN0YXRlKCd1c2VyJywge1xuICAgIHVybDogJy91c2VyLzp1c2VySWQnLFxuICAgIHRlbXBsYXRlVXJsOiAnL2pzL3VzZXIvdXNlci5odG1sJyxcbiAgICBjb250cm9sbGVyOiBmdW5jdGlvbiAoJHNjb3BlLCBmaW5kVXNlcikge1xuICAgICAgJHNjb3BlLnVzZXIgPSBmaW5kVXNlcjtcbiAgICB9LFxuICAgIHJlc29sdmU6IHtcbiAgICAgIGZpbmRVc2VyOiBmdW5jdGlvbiAoJHN0YXRlUGFyYW1zLCBVc2VyRmFjdG9yeSkge1xuICAgICAgICByZXR1cm4gVXNlckZhY3RvcnkuZ2V0QnlJZCgkc3RhdGVQYXJhbXMudXNlcklkKVxuICAgICAgICAudGhlbihmdW5jdGlvbih1c2VyKXtcbiAgICAgICAgICByZXR1cm4gdXNlcjtcbiAgICAgICAgfSk7XG4gICAgfVxuICAgIH1cbiAgfSk7XG59KTtcbiIsImFwcC5jb25maWcoZnVuY3Rpb24oJHN0YXRlUHJvdmlkZXIpe1xuXHQkc3RhdGVQcm92aWRlci5zdGF0ZSgndXNlcnMnLCB7XG5cdFx0dXJsOiAnL3VzZXJzJyxcblx0XHR0ZW1wbGF0ZVVybDogJy9qcy91c2Vycy91c2Vycy5odG1sJyxcblx0XHRyZXNvbHZlOntcblx0XHRcdHVzZXJzOiBmdW5jdGlvbihVc2VyRmFjdG9yeSl7XG5cdFx0XHRcdHJldHVybiBVc2VyRmFjdG9yeS5nZXRBbGwoKTtcblx0XHRcdH1cblx0XHR9LFxuXHRcdGNvbnRyb2xsZXI6IGZ1bmN0aW9uICgkc2NvcGUsIHVzZXJzLCBTZXNzaW9uLCAkc3RhdGUpIHtcblx0XHRcdCRzY29wZS51c2VycyA9IHVzZXJzO1xuXG4gICAgICAgICAgICAvL1dIWSBOT1QgT04gU0VTU0lPTj8/Pz9cblx0XHRcdC8vIGlmICghU2Vzc2lvbi51c2VyIHx8ICFTZXNzaW9uLnVzZXIuaXNBZG1pbil7XG5cdFx0XHQvLyBcdCRzdGF0ZS5nbygnaG9tZScpO1xuXHRcdFx0Ly8gfVxuXHRcdH1cbn0pO1xufSk7XG4iLCJhcHAuZmFjdG9yeSgnRHdlZXRGYWN0b3J5JywgZnVuY3Rpb24gKCRodHRwKSB7XG4gICAgdmFyIER3ZWV0cyA9IGZ1bmN0aW9uKHByb3BzKSB7XG4gICAgICAgIGFuZ3VsYXIuZXh0ZW5kKHRoaXMsIHByb3BzKTtcbiAgICB9O1xuXG4gICAgRHdlZXRzLmdldEFsbCA9IGZ1bmN0aW9uICgpe1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2RhdGEnKVxuICAgICAgICAudGhlbihmdW5jdGlvbiAocmVzcG9uc2Upe1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pXG5cdH07XG5cbiAgICBEd2VldHMuZ2V0TGF0ZXN0ID0gZnVuY3Rpb24gKCkge1xuICAgICAgICByZXR1cm4gJGh0dHAuZ2V0KCcvYXBpL2RhdGEvbGF0ZXN0JylcbiAgICAgICAgLnRoZW4gKGZ1bmN0aW9uIChyZXNwb25zZSkge1xuICAgICAgICAgICAgcmV0dXJuIHJlc3BvbnNlLmRhdGE7XG4gICAgICAgIH0pXG4gICAgfTtcblxuICAgIER3ZWV0cy5wb3N0QWxlcnQgPSBmdW5jdGlvbiAoYWxlcnQpIHtcbiAgICAgICAgcmV0dXJuICRodHRwLnBvc3QoJy9hcGkvYWxlcnRzJywgYWxlcnQpXG4gICAgICAgIC50aGVuICggZnVuY3Rpb24gKHJlc3BvbnNlKSB7XG4gICAgICAgICAgICByZXR1cm4gcmVzcG9uc2UuZGF0YTtcbiAgICAgICAgfSk7XG4gICAgfTtcblxuICAgIHJldHVybiBEd2VldHM7XG59KVxuIiwiYXBwLmZhY3RvcnkoJ1VzZXJGYWN0b3J5JywgZnVuY3Rpb24oJGh0dHApe1xuXG5cdHZhciBVc2VyID0gZnVuY3Rpb24ocHJvcHMpe1xuXHRcdGFuZ3VsYXIuZXh0ZW5kKHRoaXMsIHByb3BzKTtcblx0fTtcblxuXHRVc2VyLmdldEFsbCA9IGZ1bmN0aW9uICgpe1xuXHRcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvdXNlcnMnKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cdFVzZXIuZ2V0QnlJZCA9IGZ1bmN0aW9uIChpZCkge1xuXHRcdHJldHVybiAkaHR0cC5nZXQoJy9hcGkvdXNlcnMvJyArIGlkKVxuXHRcdC50aGVuKGZ1bmN0aW9uKHJlc3BvbnNlKXtcblx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cdFVzZXIuZWRpdCA9IGZ1bmN0aW9uIChpZCwgcHJvcHMpIHtcblx0XHRyZXR1cm4gJGh0dHAucHV0KCcvYXBpL3VzZXJzLycgKyBpZCwgcHJvcHMpXG5cdFx0LnRoZW4oZnVuY3Rpb24ocmVzcG9uc2Upe1xuXHRcdFx0cmV0dXJuIHJlc3BvbnNlLmRhdGE7XG5cdFx0fSk7XG5cdH07XG5cblx0VXNlci5kZWxldGUgPSBmdW5jdGlvbiAoaWQpIHtcblx0XHRyZXR1cm4gJGh0dHAuZGVsZXRlKCcvYXBpL3VzZXJzLycgKyBpZClcblx0XHQudGhlbihmdW5jdGlvbihyZXNwb25zZSl7XG5cdFx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhO1xuXHRcdH0pO1xuXHR9O1xuXG5cblx0cmV0dXJuIFVzZXI7XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoJ2R3ZWV0TGlzdCcsIGZ1bmN0aW9uKCl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy9jb21tb24vZGlyZWN0aXZlcy9kd2VldC9kd2VldC1saXN0Lmh0bWwnXG4gIH07XG59KTtcbiIsImFwcC5kaXJlY3RpdmUoXCJlZGl0QnV0dG9uXCIsIGZ1bmN0aW9uICgpIHtcblx0cmV0dXJuIHtcblx0XHRyZXN0cmljdDogJ0VBJyxcblx0XHR0ZW1wbGF0ZVVybDogJ2pzL2NvbW1vbi9kaXJlY3RpdmVzL2VkaXQtYnV0dG9uL2VkaXQtYnV0dG9uLmh0bWwnLFxuXHR9O1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCduYXZiYXInLCBmdW5jdGlvbiAoJHJvb3RTY29wZSwgQXV0aFNlcnZpY2UsIEFVVEhfRVZFTlRTLCAkc3RhdGUpIHtcblxuICAgIHJldHVybiB7XG4gICAgICAgIHJlc3RyaWN0OiAnRScsXG4gICAgICAgIHNjb3BlOiB7fSxcbiAgICAgICAgdGVtcGxhdGVVcmw6ICdqcy9jb21tb24vZGlyZWN0aXZlcy9uYXZiYXIvbmF2YmFyLmh0bWwnLFxuICAgICAgICBsaW5rOiBmdW5jdGlvbiAoc2NvcGUpIHtcblxuICAgICAgICAgICAgc2NvcGUuaXRlbXMgPSBbXG4gICAgICAgICAgICAgICAgeyBsYWJlbDogJ0FsZXJ0cycsIHN0YXRlOiAnYWxlcnRzJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdEYXRhJywgc3RhdGU6ICdkYXRhJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdMYXRlc3QnLCBzdGF0ZTogJ2xhdGVzdCcgfSxcbiAgICAgICAgICAgICAgICB7IGxhYmVsOiAnVXNlcnMnLCBzdGF0ZTogJ3VzZXJzJyB9LFxuICAgICAgICAgICAgICAgIHsgbGFiZWw6ICdEb2N1bWVudGF0aW9uJywgc3RhdGU6ICdkb2NzJyB9XG4gICAgICAgICAgICBdO1xuXG4gICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcblxuICAgICAgICAgICAgc2NvcGUuaXNMb2dnZWRJbiA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gQXV0aFNlcnZpY2UuaXNBdXRoZW50aWNhdGVkKCk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICBzY29wZS5sb2dvdXQgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgQXV0aFNlcnZpY2UubG9nb3V0KCkudGhlbihmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgICAgICAgICAkc3RhdGUuZ28oJ2hvbWUnKTtcbiAgICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHZhciBzZXRVc2VyID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgICAgICAgIEF1dGhTZXJ2aWNlLmdldExvZ2dlZEluVXNlcigpLnRoZW4oZnVuY3Rpb24gKHVzZXIpIHtcbiAgICAgICAgICAgICAgICAgICAgc2NvcGUudXNlciA9IHVzZXI7XG4gICAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgICB9O1xuXG4gICAgICAgICAgICB2YXIgcmVtb3ZlVXNlciA9IGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgICAgICBzY29wZS51c2VyID0gbnVsbDtcbiAgICAgICAgICAgIH07XG5cbiAgICAgICAgICAgIHNldFVzZXIoKTtcblxuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9naW5TdWNjZXNzLCBzZXRVc2VyKTtcbiAgICAgICAgICAgICRyb290U2NvcGUuJG9uKEFVVEhfRVZFTlRTLnNpZ251cFN1Y2Nlc3MsIHNldFVzZXIpO1xuICAgICAgICAgICAgJHJvb3RTY29wZS4kb24oQVVUSF9FVkVOVFMubG9nb3V0U3VjY2VzcywgcmVtb3ZlVXNlcik7XG4gICAgICAgICAgICAkcm9vdFNjb3BlLiRvbihBVVRIX0VWRU5UUy5zZXNzaW9uVGltZW91dCwgcmVtb3ZlVXNlcik7XG5cbiAgICAgICAgfVxuXG4gICAgfTtcblxufSk7XG4iLCJhcHAuZGlyZWN0aXZlKFwiZWRpdFBhc3NCdXR0b25cIiwgZnVuY3Rpb24gKCkge1xuXHRyZXR1cm4ge1xuXHRcdHJlc3RyaWN0OiAnRUEnLFxuXHRcdHRlbXBsYXRlVXJsOiAnanMvY29tbW9uL2RpcmVjdGl2ZXMvZWRpdC1wYXNzLWJ1dHRvbi9lZGl0LXBhc3MtYnV0dG9uLmh0bWwnLFxuXHR9O1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCd1c2VyRGV0YWlsJywgZnVuY3Rpb24oVXNlckZhY3RvcnksICRzdGF0ZVBhcmFtcywgJHN0YXRlLCBTZXNzaW9uKXtcbiAgcmV0dXJuIHtcblx0cmVzdHJpY3Q6ICdFJyxcblx0dGVtcGxhdGVVcmw6ICcvanMvY29tbW9uL2RpcmVjdGl2ZXMvdXNlci91c2VyLWRldGFpbC91c2VyLWRldGFpbC5odG1sJyxcblx0bGluazogZnVuY3Rpb24gKHNjb3BlKXtcblx0XHRzY29wZS5pc0RldGFpbCA9IHRydWU7XG5cdFx0c2NvcGUuaXNBZG1pbiA9IFNlc3Npb24udXNlci5pc0FkbWluO1xuXHRcdHNjb3BlLmVkaXRNb2RlID0gZmFsc2U7XG4gICAgICAgIHNjb3BlLmVkaXRQYXNzID0gZmFsc2U7XG5cbiAgICAgICAgLy9GSVggVEhJUyBMSU5FXG4gICAgICAgIGlmIChzY29wZS51c2VyID0gU2Vzc2lvbi51c2VyKSBzY29wZS5pc093bmVyID0gdHJ1ZVxuXG5cdFx0c2NvcGUuZW5hYmxlRWRpdCA9IGZ1bmN0aW9uICgpIHtcblx0XHRcdHNjb3BlLmNhY2hlZCA9IGFuZ3VsYXIuY29weShzY29wZS51c2VyKTtcblx0XHRcdHNjb3BlLmVkaXRNb2RlID0gdHJ1ZTtcblx0XHR9O1xuXHRcdHNjb3BlLmNhbmNlbEVkaXQgPSBmdW5jdGlvbigpe1xuXHRcdFx0c2NvcGUudXNlciA9IGFuZ3VsYXIuY29weShzY29wZS5jYWNoZWQpO1xuXHRcdFx0c2NvcGUuZWRpdE1vZGUgPSBmYWxzZTtcbiAgICAgICAgICAgIHNjb3BlLmVkaXRQYXNzPSBmYWxzZTtcblx0XHR9O1xuXHRcdHNjb3BlLnNhdmVVc2VyID0gZnVuY3Rpb24gKHVzZXIpIHtcblx0XHRcdFVzZXJGYWN0b3J5LmVkaXQodXNlci5faWQsIHVzZXIpXG5cdFx0XHQudGhlbihmdW5jdGlvbiAodXBkYXRlZFVzZXIpIHtcblx0XHRcdFx0c2NvcGUudXNlciA9IHVwZGF0ZWRVc2VyO1xuXHRcdFx0XHRzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHNjb3BlLmVkaXRQYXNzPSBmYWxzZTtcblx0XHRcdH0pO1xuXHRcdH07XG5cdFx0c2NvcGUuZGVsZXRlVXNlciA9IGZ1bmN0aW9uKHVzZXIpe1xuXHRcdFx0VXNlckZhY3RvcnkuZGVsZXRlKHVzZXIpXG5cdFx0XHQudGhlbihmdW5jdGlvbigpe1xuXHRcdFx0XHRzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIHNjb3BlLmVkaXRQYXNzPSBmYWxzZTtcblx0XHRcdFx0JHN0YXRlLmdvKCdob21lJyk7XG5cdFx0XHR9KTtcblx0XHR9O1xuXG4gICAgICAgIHNjb3BlLnBhc3N3b3JkRWRpdCA9IGZ1bmN0aW9uKCl7XG4gICAgICAgICAgICAvLyBVc2VyRmFjdG9yeS5lZGl0KGlkLCB7J25ld1Bhc3MnOiB0cnVlfSlcbiAgICAgICAgICAgIC8vIC50aGVuKGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICAgIC8vICAgICAvLyBzY29wZS5uZXdQYXNzID0gdHJ1ZTtcbiAgICAgICAgICAgIC8vICAgICBzY29wZS5lZGl0TW9kZSA9IGZhbHNlO1xuICAgICAgICAgICAgLy8gfSk7XG4gICAgICAgICAgICBzY29wZS5jYWNoZWQgPSBhbmd1bGFyLmNvcHkoc2NvcGUudXNlcik7XG4gICAgICAgICAgICBzY29wZS5lZGl0UGFzcyA9IHRydWU7XG4gICAgICAgIH07XG5cdH0sXG5cdHNjb3BlOiB7XG5cdFx0dXNlcjogXCI9XCJcblx0fVxuICB9O1xufSk7XG4iLCJhcHAuZGlyZWN0aXZlKCd1c2VyTGlzdCcsIGZ1bmN0aW9uKCl7XG4gIHJldHVybiB7XG4gICAgcmVzdHJpY3Q6ICdFJyxcbiAgICB0ZW1wbGF0ZVVybDogJy9qcy9jb21tb24vZGlyZWN0aXZlcy91c2VyL3VzZXItbGlzdC91c2VyLWxpc3QuaHRtbCdcbiAgfTtcbn0pO1xuIl0sInNvdXJjZVJvb3QiOiIvc291cmNlLyJ9
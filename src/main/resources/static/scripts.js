var app = new Vue({
    el: "#app",
    data: {
        newMessage: null,
        messages: [],
        authToken: null,
        sendColor: null
    },
    methods: {
        scrollToEnd: function () {
            var container = document.getElementById("messages");
            var scrollHeight = container.scrollHeight;
            container.scrollTop = scrollHeight;
        },
        sendMessage: function () {
            if (this.newMessage == null || this.newMessage.trim() == "") {
                return;
            }
            if (this.authToken == null) {
                return;
            }
            var that = this;
            var formData = new FormData();
            formData.append("message", that.newMessage);
            axios.post("/api/messages", formData).then(function (resp) {
                that.newMessage = null;
                that.sendColor = null;
            }).catch(function () {
                that.authToken = null;
                that.sendColor = "error";
            });
        },
        fetchAuthToken: function () {
            var that = this;
            axios.get("/api/me").then(function (resp) {
                that.authToken = resp.headers["authorization"];
                axios.defaults.headers.common["Authorization"] = that.authToken;
                sessionStorage.setItem("authToken", that.authToken);
            }).catch(function () {
                that.authToken = null;
                axios.defaults.headers.common["Authorization"] = null;
                sessionStorage.removeItem("authToken");
            });
        },
        refreshUI: function () {
            var tag = new Date().getTime();
            for (var i = 0; i < this.messages.length; ++i) {
                this.messages[i].refreshTag = tag;
            }
        },
        login: function () {
            window.location.href = "/login";
        },
        addMessage: function (msg) {
            msg.refreshTag = new Date().getTime();

            // Limit how many messages are displayed in the browser,
            // to reduce memory usage.
            var maxMessages = 50;
            if (this.messages.length > maxMessages) {
                this.messages = this.messages.slice(this.messages.length - maxMessages);
            }
            this.messages.push(msg);
        }
    },
    filters: {
        moment: function (date) {
            return moment(date).startOf("second").fromNow();
        }
    },
    created() {
        var that = this;
        setInterval(function () {
            that.refreshUI();
        }.bind(this), 60000);
    },
    updated() {
        this.scrollToEnd();
    },
    mounted() {
        this.authToken = sessionStorage.getItem("authToken");
        axios.defaults.headers.common["Authorization"] = this.authToken;

        if (this.authToken == null) {
            this.fetchAuthToken();
        }
        setupEventSource();
    }
});


// This snippet comes from this page:
// https://stackoverflow.com/a/54385402/422906

function isFunction(functionToCheck) {
    return functionToCheck && {}.toString.call(functionToCheck) === '[object Function]';
}

function debounce(func, wait) {
    var timeout;
    var waitFunc;

    return function () {
        if (isFunction(wait)) {
            waitFunc = wait;
        } else {
            waitFunc = function () {
                return wait
            };
        }

        var context = this, args = arguments;
        var later = function () {
            timeout = null;
            func.apply(context, args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, waitFunc());
    };
}

// reconnectFrequencySeconds doubles every retry
var reconnectFrequencySeconds = 1;
var evtSource;

var reconnectFunc = debounce(function () {
    setupEventSource();
    // Double every attempt to avoid overwhelming server
    reconnectFrequencySeconds *= 2;
    // Max out at ~1 minute as a compromise between user experience and server load
    if (reconnectFrequencySeconds >= 64) {
        reconnectFrequencySeconds = 64;
    }
}, function () {
    return reconnectFrequencySeconds * 1000
});

function setupEventSource() {
    evtSource = new EventSource("/api/messages/sse");
    evtSource.onmessage = function (e) {
        var msg = JSON.parse(e.data);
        app.addMessage(msg);
    };
    evtSource.onopen = function (e) {
        // Reset reconnect frequency upon successful connection
        reconnectFrequencySeconds = 1;
    };
    evtSource.onerror = function (e) {
        evtSource.close();
        reconnectFunc();
    };
}

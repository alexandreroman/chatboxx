var app = new Vue({
    el: "#app",
    data: {
        newMessage: null,
        messages: [],
        authToken: null,
        sendColor: null
    },
    methods: {
        init: function () {
            var evtSource = new EventSource("/api/messages/sse");
            var that = this;
            evtSource.addEventListener("message", function (e) {
                var msg = JSON.parse(e.data);
                msg.refreshTag = new Date().getTime();
                that.messages.push(msg);
            }, false);
            evtSource.addEventListener("close", function (e) {
                evtSource.close();
            }, false);
        },
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
                var that = this;
                axios.get("/api/me").then(function (resp) {
                    that.authToken = resp.headers["authorization"];
                    axios.defaults.headers.common["Authorization"] = that.authToken;
                    that._doSendMessage();
                });
            } else {
                this._doSendMessage();
            }
        },
        _doSendMessage: function () {
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
        refresh: function () {
            var tag = new Date().getTime();
            for (var i = 0; i < this.messages.length; ++i) {
                this.messages[i].refreshTag = tag;
            }
        }
    },
    filters: {
        moment: function (date) {
            return moment(date).startOf("second").fromNow();
        }
    },
    created() {
        this.init();

        var that = this;
        setInterval(function () {
            that.refresh();
        }.bind(this), 60000);
    },
    updated() {
        this.scrollToEnd();
    }
});

var app = new Vue({
    el: "#app",
    data: {
        newMessage: null,
        messages: []
    },
    methods: {
        init: function () {
            var evtSource = new EventSource("/api/messages/sse");
            var that = this;
            evtSource.addEventListener("message", function (e) {
                var msg = JSON.parse(e.data);
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
            var that = this;
            var formData = new FormData();
            formData.append("message", that.newMessage);
            axios.post("/api/messages", formData).then(function (response) {
                that.newMessage = null;
            });
        }
    },
    filters: {
        moment: function (date) {
            return moment(date).startOf("second").fromNow();
        }
    },
    created() {
        this.init();
    },
    updated() {
        this.scrollToEnd();
    }
});

import bridge from '../../common/bridge.js';

export default {
    data: {
        reply: 'Tap and the phone answers'
    },
    onInit() {
        var that = this;
        bridge.listen(function (message) {
            if (message.t === 'hello') {
                that.reply = message.s || 'The phone answered';
            }
        });
        bridge.start(function (problem) {
            if (problem) {
                that.reply = 'Link: ' + problem;
            }
        });
    },
    onDestroy() {
        bridge.listen(null);
    },
    sayHello() {
        var that = this;
        this.reply = 'Sending…';
        bridge.send({ t: 'hello' }, function (ok) {
            if (!ok) {
                that.reply = 'Could not reach the phone (is HuaSideload open?)';
            }
        });
    }
};

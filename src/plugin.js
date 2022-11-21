module.exports = class esex {
    constructor(meta) {
    }
    start() {
        // load keys
        this.keypair = BdApi.Data.load("esex", "keypair");
        // if we have one saved
        if (this.keypair) {
            // decode the keypair
            this.keypair = {
                publicKey: nacl.util.decodeBase64(this.keypair.publicKey),
                secretKey: nacl.util.decodeBase64(this.keypair.secretKey)
            };
        }
        // if we don't
        else {
            // create a keypair
            this.keypair = nacl.sign.keyPair();
            // save it
            BdApi.Data.save("esex", "keypair", {
                publicKey: nacl.util.encodeBase64(this.keypair.publicKey),
                secretKey: nacl.util.encodeBase64(this.keypair.secretKey)
            });
        }

        // monkeypatch into the send message function
        this.clearSendMessagePatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("sendMessage"), "sendMessage", (ctx, args) => {
            let dmId = args[0];
            let messageContent = args[1];
            console.log(dmId);
            console.log(messageContent);
        });

        // monkeypatch into the edit message function
        this.clearEditMessagePatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("editMessage"), "editMessage", (ctx, args) => {
            let dmId = args[0];
            let messageContent = args[2];
            console.log(dmId);
            console.log(messageContent);
        });

        // monkeypatch into our event dispatchers
        this.clearEventPatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("dispatch", "subscribe"), "dispatch", (ctx, args) => {
            // get the event
            let event = args[0];
            // if a message was received or an edit to a message was received
            if (event.type === "MESSAGE_CREATE" || event.type === "MESSAGE_UPDATE") {
            }
            // if multiple messages were loaded
            else if (["LOAD_MESSAGES_SUCCESS", "LOAD_MESSAGES_AROUND_SUCCESS", "LOAD_RECENT_MENTIONS_SUCCESS", "LOAD_PINNED_MESSAGES_SUCCESS"].includes(event.type)) {
            }
            // if a channel was selected
            else if (event.type === "CHANNEL_SELECT") {
                this.inDM = event.guildId === null;
                this.channelId = event.channelId;
            }
        });
    }
    stop() {
        // clear all patches
        this.clearSendMessagePatch();
        this.clearEditMessagePatch();
        this.clearEventPatch();
    }
};
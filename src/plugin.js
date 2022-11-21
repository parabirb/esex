// plugin export
module.exports = class esex {
    start() {
        // load keys
        this.keypair = BdApi.Data.load("esex", "keypair");
        // if we have one saved
        if (this.keypair) {
            // decode the keypair
            this.keypair = {
                publicKey: brailleToBytes(this.keypair.publicKey),
                secretKey: brailleToBytes(this.keypair.secretKey)
            };
        }
        // if we don't
        else {
            // create a keypair
            this.keypair = nacl.sign.keyPair();
            // save it
            BdApi.Data.save("esex", "keypair", {
                publicKey: bytesToBraille(this.keypair.publicKey),
                secretKey: bytesToBraille(this.keypair.secretKey)
            });
        }

        // monkeypatch into the send message function
        this.clearSendMessagePatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("sendMessage"), "sendMessage", (ctx, args) => {
            let dmId = args[0];
            let messageContent = args[1];
        });

        // monkeypatch into the edit message function
        this.clearEditMessagePatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("editMessage"), "editMessage", (ctx, args) => {
            let dmId = args[0];
            let messageContent = args[2];
        });

        // monkeypatch into the event dispatcher
        this.clearEventPatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("dispatch", "subscribe"), "dispatch", (ctx, args) => {
            // get the event
            let event = args[0];
            // if a message was received or an edit to a message was received
            if (event.type === "MESSAGE_CREATE" || event.type === "MESSAGE_UPDATE") {
                // return if we're not in a DM or there's no session
                if (!this.inDM) return;

            }
            // if multiple messages were loaded
            else if (["LOAD_MESSAGES_SUCCESS", "LOAD_MESSAGES_AROUND_SUCCESS", "LOAD_RECENT_MENTIONS_SUCCESS", "LOAD_PINNED_MESSAGES_SUCCESS"].includes(event.type)) {
                // return if we're not in a DM or there's no session
                if (!this.inDM) return;

            }
            // if a channel was selected
            else if (event.type === "CHANNEL_SELECT") {
                // set variables
                this.inDM = event.guildId === null;
                this.channelId = event.channelId;
                this.cryptData = BdApi.Data.load("esex", this.channelID);
                this.session = (this.cryptData && this.cryptData.state === "encrypted") ? new secretSession(this.cryptData) : null;
                this.encryption = this.session ? true : false;
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
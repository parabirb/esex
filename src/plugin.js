// plugin export
module.exports = class esex {
    // decrypt message
    decryptMessage(message) {
        // if it's in a guild, return
        if (message.guild_id) return message.content;
        // decode the braille data
        let decodedMessage = decodeMessage(message.content);
        // load crypt data for the message
        let cryptData = BdApi.Data.load("esex", message.channel_id);
        // if there's no braille message, return but with insecure
        if (!decodedMessage) return `[insecure] ${message.content}`;
        // if we don't have any crypt data and the message isn't a handshake, return
        if (!cryptData && message.type !== "initHandshake") return `[insecure] ${message.content}`;
        // if the braille's in our crypt data
        let brailleHash = bytesToBraille(nacl.hash(nacl.util.decodeUTF8(message.content)));
        if (cryptData.messages[brailleHash]) {
            return cryptData.messages[brailleHash];
        }
        // if it's a handshake and we have cryptdata
        if (cryptData && decodedMessage.type === "initHandshake") {
            return "[esex] This message is invalid (reason: handshake attempt after init, if you are trying to renegotiate run `esex-bd clear` first)";
        }
        // if it's a handshake
        else if (decodedMessage.type === "initHandshake") {
            // create a session object
            let session = new secretSession();
            // convert ed25519 keypair to x25519 keypair
            let identity = ed2curve.convertKeyPair(this.keypair);
            // generate a handshake key
            let handshake = nacl.box.keyPair();
            // set the session up
            session
                .identity(identity)
                .handshake(handshake)
                .theirIdentity(decodedMessage.payload.identityKey)
                .theirHandshake(decodedMessage.payload.handshakeKey)
                .setRole("receiver")
                .computeMasterKey();
            // encode handshake message
            let encodedHandshake = encodeHandshake(this.keypair.publicKey, nacl.sign(handshake.publicKey, this.keypair.secretKey), "handshakeReply");
            // create the cryptdata object
            cryptData = {
                state: "encrypted",
                session: session.export(),
                messages: {}
            };
            cryptData.messages[brailleHash] = "[esex] Handshake initialize";
            cryptData.messages[bytesToBraille(nacl.hash(nacl.util.decodeUTF8(encodedHandshake)))] = "[esex] Handshake reply";
            // save it
            BdApi.Data.save("esex", message.channel_id, cryptData);
            // send handshake message
            BdApi.findModuleByProps("sendMessage").sendMessage(message.channel_id, {content: encodedHandshake});
            // return the message content
            return "[esex] Handshake initialize";
        }
        // if we don't have cryptdata
        else if (!cryptData) {
            // return invalid message
            return "[esex] This message is invalid (reason: no crypt data)";
        }
        // if it's a handshake reply
        else if (cryptData.state !== "encrypted" && decodedMessage.type === "handshakeReply") {
            // create a session object
            let session = new secretSession(cryptData.session);
            // set the session up fully
            session
                .theirIdentity(decodedMessage.payload.identityKey)
                .theirHandshake(decodedMessage.payload.handshakeKey)
                .computeMasterKey();
            // modify cryptdata object
            cryptData.state = "encrypted";
            cryptData.session = session.export();
            cryptData.messages[brailleHash] = "[esex] Handshake reply";
            // save the cryptdata
            BdApi.Data.save("esex", message.channel_id, cryptData);
            // return the message content
            return "[esex] Handshake reply";
        }
        // if it's a message
        else if (cryptData.state === "encrypted" && decodedMessage.type === "message") {
            // try
            try {
                // decrypt
                let {cleartext} = session.decrypt(decodedMessage.payload);
                // modify cryptdata object
                cryptData.messages[brailleHash] = cleartext;
                // save thee cryptdata
                BdApi.Data.save("esex", message.channel_id, cryptData);
                // return the cleartext
                return cleartext;
            }
            // catch
            catch (e) {
                return "[esex] Invalid message (reason: could not decrypt)";
            }
        }
        // otherwise
        else {
            // return invalid message
            return "[esex] Invalid message (reason: could not recognize)";
        }
    }

    // start function
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
            // return if we aren't in a DM
            if (!this.inDM) return;
            // get the dm id and message content
            let dmId = args[0];
            let message = args[1];
            // refresh cryptdata
            this.cryptData = BdApi.Data.load("esex", this.channelId);
            this.session = this.cryptData ? new secretSession(this.cryptData.session) : null;
            console.log(message);
            // if it's the help command
            if (message.content === "esex-bd help") {
                // alert
                BdApi.UI.alert("esex help", `Commands can only be run in DMs. Images are not encrypted.
\`\`\`
esex-bd init - Start a session with the open user.
esex-bd clear - Clear session data for the open user.
esex-bd safety - Prints out safety braille with the open user.
esex-bd insecure (text) - Sends a message insecurely to the open user.
\`\`\``);
                // set message content to nothing
                message.content = "";
            }
            // if it's the clear command
            else if (this.session && message.content === "esex-bd clear") {
                // clear the session
                BdApi.Data.delete("esex", this.channelId);
                this.cryptData = undefined;
                this.session = null;
                // alert
                BdApi.UI.alert("esex", "Your session with the active user was cleared.");
                // set message content to nothing
                message.content = "";
            }
            // if it's the safety braille
            else if (this.session && cryptData.state === "encrypted" && message.content === "esex-bd safety") {
                // alert with the safety braille
                BdApi.UI.alert("esex safety braille", `If your braille looks the same as that of the other person's, your connection is secure.
\`\`\`
${bytestoBraille(nacl.hash(this.session.identityKey > this.session.theirIdentityKey ? new Uint8Array([...this.session.identityKey, ...this.session.theirIdentityKey]) : new Uint8Array([...this.session.theirIdentityKey, ...this.session.identityKey])).slice(0, 24))}
\`\`\``);
                // set message content to nothing
                message.content = "";
            }
            // if it's the initiate command
            else if (!this.session && message.content === "esex-bd init") {
                // create a session object
                this.session = new secretSession();
                // convert ed25519 keypair to x25519 keypair
                let identity = ed2curve.convertKeyPair(this.keypair);
                // generate a handshake key
                let handshake = nacl.box.keyPair();
                // set the session up
                this.session
                    .identity(identity)
                    .handshake(handshake)
                    .setRole("initiator");
                // encode handshake message
                let encodedHandshake = encodeHandshake(this.keypair.publicKey, nacl.sign(handshake.publicKey, this.keypair.secretKey), "initHandshake");
                // create the cryptdata object
                this.cryptData = {
                    state: "handshaking",
                    session: this.session.export(),
                    messages: {}
                };
                this.cryptData.messages[bytesToBraille(nacl.hash(nacl.util.decodeUTF8(encodedHandshake)))] = "[esex] Handshake initialize";
                // save it
                BdApi.Data.save("esex", this.channelId, this.cryptData);
                // set message content to the handshake
                message.content = encodedHandshake;
            }
            // if it's the insecure command
            else if (message.content.startsWith("esex-bd insecure ")) {
                // send the message insecurely
                message.content = message.content.slice(17);
            }
            // if there's a session
            else if (this.session) {
                // encrypt the message
                let msg = encodeMessage(this.session.encrypt(message.content));
                // modify cryptdata
                this.cryptData.session = this.session.export();
                this.cryptData[bytesToBraille(nacl.hash(nacl.util.decodeUTF8(msg)))] = message.content;
                // save cryptdata
                BdApi.Data.save("esex", this.channelId, this.cryptData);
                // set the message
                message.content = msg;
            }
        });

        // monkeypatch into the edit message function
        this.clearEditMessagePatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("editMessage"), "editMessage", (ctx, args) => {
            // return if we aren't in a DM
            if (!this.inDM) return;
            // refresh cryptdata
            this.cryptData = BdApi.Data.load("esex", this.channelId);
            this.session = this.cryptData ? new secretSession(this.cryptData.session) : null;
            // if we're not in a session we can just return
            if (!this.cryptData || !this.cryptData.state !== "encrypted") return;
            // get the message content
            let message = args[2];
            // encrypt it
            let brailleMessage = encodeMessage(this.session.encrypt(message));
            // modify cryptdata
            this.cryptData.session = this.session.export();
            this.cryptData[bytesToBraille(nacl.hash(nacl.util.decodeUTF8(brailleMessage)))] = message;
            // save the cryptdata
            BdApi.Data.save("esex", this.channelId, this.cryptData);
            // set the message
            message.content = brailleMessage;
        });

        // monkeypatch into the event dispatcher
        this.clearEventPatch = BdApi.Patcher.before("esex", BdApi.findModuleByProps("dispatch", "subscribe"), "dispatch", (ctx, args) => {
            // get the event
            let event = args[0];
            // if a message was received or an edit to a message was received
            if (event.type === "MESSAGE_CREATE" || event.type === "MESSAGE_UPDATE") {
                event.message.content = this.decryptMessage(event.message);
            }
            // if multiple messages were loaded
            else if (["LOAD_MESSAGES_SUCCESS", "LOAD_MESSAGES_AROUND_SUCCESS", "LOAD_RECENT_MENTIONS_SUCCESS", "LOAD_PINNED_MESSAGES_SUCCESS"].includes(event.type)) {
                event.messages.forEach(x => x.content = this.decryptMessage(x));
            }
            // if a channel was selected
            else if (event.type === "CHANNEL_SELECT") {
                // set variables
                this.inDM = event.guildId === null;
                this.channelId = event.channelId;
                this.cryptData = BdApi.Data.load("esex", this.channelId);
                this.session = this.cryptData ? new secretSession(this.cryptData.session) : null;
            }
        });
    }

    // stop function
    stop() {
        // clear all patches
        this.clearSendMessagePatch();
        this.clearEditMessagePatch();
        this.clearEventPatch();
    }
};
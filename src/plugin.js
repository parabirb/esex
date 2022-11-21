// populate the braille space
let brailleSpace = ["•"];
for (let i = 1; i < 256; i++) {
    brailleSpace.push(String.fromCharCode(0x2800 + i));
}
// function for verifying braille correctness
function verifyBraille(text) {
    for (let letter of text) {
        if (!brailleSpace.includes(letter)) return false;
    }
    return true;
}
// function to convert braille to bytes
function brailleToBytes(braille) {
    return new Uint8Array(braille.split("").map(x => brailleSpace.indexOf(x)));
}
// function to convert bytes to braille
function bytesToBraille(bytes) {
    return [...bytes].map(x => brailleSpace[x]).join("");
}
// function to convert braille to base64
function brailleToBase64(braille) {
    return nacl.util.encodeBase64(brailleToBytes(braille));
}
// function to convert base64 to braille
function base64ToBraille(base64) {
    return bytesToBraille(nacl.util.decodeBase64(base64));
}

// message types
const messageTypes = ["initHandshake", "handshakeReply", "message"];

// function for decoding the message format
function decodeMessage(message) {
    // if the message isn't encoded properly, return
    if (!verifyBraille(message)) return null;
    // decode bytes
    let bytes = brailleToBytes(message);
    // get the message type number
    let msgType = bytes[0];
    // if it's invalid, return
    if (msgType >= messageTypes.length) return null;
    // convert the message type number into a message type
    msgType = messageTypes[msgType];
    // if it's a handshake initialization or handshake reply
    if (msgType === "initHandshake" || msgType === "handshakeReply") {
        // if the length is incorrect, fail
        if (message.length !== 129) return null;
        // get the identity key
        let identityKey = brailleToBytes(message.slice(1, 33));
        // get the handshake key
        let handshakeKey = brailleToBytes(message.slice(33));
        // unwrap the handshake key's signature
        handshakeKey = nacl.sign.open(handshakeKey, identityKey);
        // if the signature can't be opened, fail
        if (handshakeKey === null) return null;
        // convert the identity key to an X25519 key
        identityKey = ed2curve.convertPublicKey(identityKey);
        // return the message
        return {
            type: msgType,
            payload: {
                identityKey,
                handshakeKey
            }
        };
    }
    // if it's a message
    else if (msgType === "message") {
        // if the length is incorrect, fail
        if (message.length <= 93) return null;
        // get the dh
        let dh = brailleToBase64(message.slice(1, 33));
        // get pn
        let pn = brailleToBytes(message.slice(33, 35));
        pn = (pn[0] << 8) + pn[1];
        // get n
        let n = brailleToBytes(message.slice(35, 37));
        n = (n[0] << 8) + n[1];
        // get the mac
        let mac = brailleToBase64(message.slice(37, 69));
        // get the nonce
        let nonce = brailleToBase64(message.slice(69, 93));
        // get the ciphertext
        let encrypted = brailleToBase64(message.slice(93));
        // return the message
        return {
            type: msgType,
            payload: {
                header: {
                    dh,
                    pn,
                    n
                },
                ciphertext: {
                    mac,
                    nonce,
                    encrypted
                }
            }
        };
    }
}
// function for encoding handshake messages
function encodeHandshake(identityKey, handshakeKey, type) {
    return `${brailleSpace[messageTypes.indexOf(type)]}${bytesToBraille(identityKey)}${bytesToBraille(handshakeKey)}`;
}
// function for encoding message
function encodeMessage(message) {
    return `${brailleSpace[messageTypes.indexOf("message")]}${base64ToBraille(message.header.dh)}${bytesToBraille([message.header.pn >> 8])}${bytesToBraille([message.header.pn & 0xff])}${bytesToBraille([message.header.n >> 8])}${bytesToBraille([message.header.n & 0xff])}${base64ToBraille(message.ciphertext.mac)}${base64ToBraille(message.ciphertext.nonce)}${base64ToBraille(message.ciphertext.encrypted)}`;
}

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
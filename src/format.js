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
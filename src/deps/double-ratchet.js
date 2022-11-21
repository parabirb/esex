/*
    BUCKLE YOUR SEATBELTS, MOTHERFUCKERS, BECAUSE IN 315
    SHORT LINES, I AM GOING TO IMPLEMENT YOU A THING THAT
    I ONLY FIGURED OUT ABOUT TWO HOURS AGO. SO SIT DOWN,
    SHUT UP, AND ENJOY THE EXPERIENCE OF MY 4 AM REDBULL
    INDUCED SELF-HATRED FUELED PROGRAMMING EXTRAVAGANZA.

    made by parabirb 2021
    public domain
    HOLY SHIT IT WORKS? MARCH 30 23:19 CDT

    modified by... parabirb?
    this version supports exporting and importing sessions. that's all that changed.
    also i changed it to support export/import. you know, normal shit like that.
*/

// _crypto will be our nacl object
let _crypto = window.nacl;

// required functions for double ratchet
const doubleRatchetFunctions = {
    // max skip
    MAX_SKIP: 1000,
    // keypair generation
    GENERATE_DH: () => _crypto.box.keyPair(),
    // diffie-hellman
    DH: (dh_pair, dh_pub) => _crypto.box.before(dh_pub, dh_pair.secretKey),
    // KDF_RK
    KDF_RK: function KDF_RK(rk, dh_out) {
        // HMAC(dh_out, rk)
        const KDF_OUTPUT = _crypto.auth.full(dh_out, rk);
        // slice our RK and CK
        return {
            rk: KDF_OUTPUT.slice(0, 32),
            ck: KDF_OUTPUT.slice(32)
        };
    },
    // KDF_CK
    KDF_CK: function KDF_CK(ck) {
        // set our constant which will be passed into the KDF
        const constant = _crypto.util.decodeUTF8("double-ratchet by parabirb");
        // apply KDF with key ck to constant
        const KDF_OUTPUT = doubleRatchetFunctions.KDF_RK(ck, constant);
        // return an object with ck and mk
        return {
            ck: KDF_OUTPUT.ck,
            mk: KDF_OUTPUT.rk
        };
    },
    // AEAD encryption
    ENCRYPT: function ENCRYPT(mk, plaintext, associated_data) {
        // get MAC for the AD
        const AD_MAC = _crypto.auth(associated_data, mk);
        // generate a nonce
        const NONCE = _crypto.randomBytes(24);
        // encrypt the plaintext
        const ENCRYPTED_TEXT = _crypto.secretbox(plaintext, NONCE, mk);
        // return ciphertext object
        return {
            mac: _crypto.util.encodeBase64(AD_MAC),
            nonce: _crypto.util.encodeBase64(NONCE),
            encrypted: _crypto.util.encodeBase64(ENCRYPTED_TEXT)
        };
    },
    // AEAD decryption
    DECRYPT: function DECRYPT(mk, ciphertext, associated_data) {
        // get MAC for the AD
        const AD_MAC = _crypto.auth(associated_data, mk);
        // STOP! YOU'VE VIOLATED THE LAW!
        if (!_crypto.verify(AD_MAC, _crypto.util.decodeBase64(ciphertext.mac))) {
            // throw an error
            throw new Error("MAC could not be verified for associated data.");
        }
        // ok now we'll unbox this :)
        const unboxed = _crypto.secretbox.open(_crypto.util.decodeBase64(ciphertext.encrypted), _crypto.util.decodeBase64(ciphertext.nonce), mk);
        // turn this into UTF-8 and return it
        return _crypto.util.encodeUTF8(unboxed);
    },
    // header formation
    HEADER: function HEADER(dh_pair, pn, n) {
        return {
            // encoded public key
            dh: _crypto.util.encodeBase64(dh_pair.publicKey),
            // pn and n
            pn,
            n
        };
    },
    // header-to-byte-sequence
    CONCAT: function CONCAT(header) {
        // convert JSON.stringify(header) to byte array lol
        return _crypto.util.decodeUTF8(JSON.stringify(header));
    },
    // convenient function
    CATMANYTHINGSPLEASE: (a, b, c) => new Uint8Array([...a, ...b, ...c]),
    // types of the various internal variables
    types: {
        identityKey: "key",
        handshakeKey: "key",
        theirHandshakeKey: "buf",
        theirIdentityKey: "buf",
        initiator: "nBuf",
        sk: "buf",
        DHs: "key",
        DHr: "buf",
        RK: "buf",
        CKs: "buf",
        CKr: "buf",
        Ns: "nBuf",
        Nr: "nBuf",
        PN: "nBuf",
        MKSKIPPED: "MKSKIPPED"
    }
};

// class for double ratchets
class doubleRatchet {
    // constructor
    constructor(data = null) {
        if (data !== null) {
            for (let key of Object.keys(data)) {
                if (doubleRatchetFunctions.types[key] === "buf") {
                    this[key] = _crypto.util.decodeBase64(data[key]);
                }
                else if (doubleRatchetFunctions.types[key] === "nBuf") {
                    this[key] = data[key];
                }
                else if (doubleRatchetFunctions.types[key] === "key") {
                    this[key] = {
                        publicKey: _crypto.util.decodeBase64(data[key].publicKey),
                        secretKey: _crypto.util.decodeBase64(data[key].secretKey)
                    }
                }
                else if (doubleRatchetFunctions.types[key] === "MKSKIPPED") {
                    let MKSKIPPED = data[key];
                    for (let mkSkippedKey of Object.keys(MKSKIPPED)) {
                        for (let secondSkippedKey of Object.keys(MKSKIPPED[mkSkippedKey])) {
                            MKSKIPPED[mkSkippedKey][secondSkippedKey] = _crypto.util.decodeBase64(MKSKIPPED[mkSkippedKey][secondSkippedKey]);
                        }
                    }
                    this[key] = MKSKIPPED;
                }
            }
        }
    }

    // set identity key
    identity(ik) {
        this.identityKey = ik;
        return this;
    }

    // set handshake key
    handshake(hk) {
        this.handshakeKey = hk;
        return this;
    }

    // set their handshake key
    theirHandshake(hk) {
        this.theirHandshakeKey = hk;
        return this;
    }

    // set their identity key
    theirIdentity(ik) {
        this.theirIdentityKey = ik;
        return this;
    }

    // set role
    setRole(role) {
        this.initiator = role === "initiator";
        return this;
    }

    // compute master key
    computeMasterKey() {
        // are we initiator?
        if (this.initiator) {
            // if so, we do:
            // nacl.hash(dh(theirHandshake, ourIdentity), dh(theirIdentity, ourHandshake), dh(theirBase, ourBase))
            this.sk = _crypto.hash(
                doubleRatchetFunctions.CATMANYTHINGSPLEASE(
                    doubleRatchetFunctions.DH(this.identityKey, this.theirHandshakeKey),
                    doubleRatchetFunctions.DH(this.handshakeKey, this.theirIdentityKey),
                    doubleRatchetFunctions.DH(this.handshakeKey, this.theirHandshakeKey)
                )
            );
            // ok so now we have the sk. what next?
            // well we generate a dh as our DHs
            this.DHs = doubleRatchetFunctions.GENERATE_DH();
            // we set our DHr to their handshake public key
            this.DHr = this.theirHandshakeKey;
            // calculate kdf_rk
            let RK_OUT = doubleRatchetFunctions.KDF_RK(this.sk, doubleRatchetFunctions.DH(this.DHs, this.DHr));
            // set rk and cks
            this.RK = RK_OUT.rk;
            this.CKs = RK_OUT.ck;
            // CKr will be our sk
            this.CKr = this.sk;
        }
        // if not
        else {
            // we need to do
            // nacl.hash(dh(theirIdentity, ourHandshake), dh(theirHandshake, ourIdentity), dh(theirBase, ourBase))
            this.sk = _crypto.hash(
                doubleRatchetFunctions.CATMANYTHINGSPLEASE(
                    doubleRatchetFunctions.DH(this.handshakeKey, this.theirIdentityKey),
                    doubleRatchetFunctions.DH(this.identityKey, this.theirHandshakeKey),
                    doubleRatchetFunctions.DH(this.handshakeKey, this.theirHandshakeKey)
                )
            );
            // wew lad what do we do now
            // DHs is our ephemeral
            this.DHs = this.handshakeKey;
            // the initiator will send us their new DH key
            this.DHr = null;
            // the RK for us will be the shared secret
            this.RK = this.sk;
            // CKs will be the sk
            this.CKs = this.sk;
            this.CKr = null;
        }
        // numbers! i love numbers!
        this.Ns = 0;
        this.Nr = 0;
        this.PN = 0;
        // mkskipped
        this.MKSKIPPED = {};
    }

    // encryption func
    encrypt(plaintext) {
        // we want our plaintext to be an array of u8s
        plaintext = _crypto.util.decodeUTF8(plaintext);
        // get CKs and MK
        let KDF_CK_OUTPUT = doubleRatchetFunctions.KDF_CK(this.CKs);
        // set CKs and MK
        this.CKs = KDF_CK_OUTPUT.ck;
        let mk = KDF_CK_OUTPUT.mk;
        // get our header
        let header = doubleRatchetFunctions.HEADER(this.DHs, this.PN, this.Ns);
        // increment Ns
        this.Ns++;
        // return our stuff
        return {
            header,
            ciphertext: doubleRatchetFunctions.ENCRYPT(mk, plaintext, doubleRatchetFunctions.CONCAT(header))
        };
    }

    // ok bubby we need these for decryption
    TrySkippedMessageKeys(header, ciphertext) {
        // dh in mkskipped?
        if (header.dh in this.MKSKIPPED) {
            // n in mkskipped?
            if (header.n in this.MKSKIPPED[header.dh]) {
                // set mk
                let mk = this.MKSKIPPED[header.dh][header.n];
                delete this.MKSKIPPED[header.dh][header.n];
                // delete the mkskipped for the dh if it's empty
                if (Object.keys(this.MKSKIPPED[header.dh]).length === 0) delete this.MKSKIPPED[header.dh];
                // decrypt
                return doubleRatchetFunctions.DECRYPT(mk, ciphertext, doubleRatchetFunctions.CONCAT(header));
            }
        }
        // no match? get out
        return false;
    }

    SkipMessageKeys(until) {
        // in reality i don't fully know what this is supposed to do
        // but it was in the docs
        if (this.Nr + doubleRatchetFunctions.MAX_SKIP < until) {
            throw new Error("until is too much");
        }
        // if we have a CKr
        if (this.CKr !== null) {
            while (this.Nr < until) {
                // get CKr and MK
                let KDF_CK_OUTPUT = doubleRatchetFunctions.KDF_CK(this.CKr);
                // set CKr and MK
                this.CKr = KDF_CK_OUTPUT.ck;
                let mk = KDF_CK_OUTPUT.mk;
                // set mkskipped DHr if it isn't already set
                if (!(_crypto.util.encodeBase64(this.DHr) in this.MKSKIPPED)) {
                    this.MKSKIPPED[_crypto.util.encodeBase64(this.DHr)] = {};
                }
                // set MKSKIPPED[DHr][Nr] to mk
                this.MKSKIPPED[_crypto.util.encodeBase64(this.DHr)][this.Nr] = mk;
                // increment Nr
                this.Nr++;
            }
        }
    }

    DHRatchet(header) {
        // le numbers
        this.PN = this.Ns;
        this.Ns = 0;
        this.Nr = 0;
        // set DHr
        this.DHr = _crypto.util.decodeBase64(header.dh);
        // calculate KDF_RK
        let KDF_RK_OUT = doubleRatchetFunctions.KDF_RK(this.RK, doubleRatchetFunctions.DH(this.DHs, this.DHr));
        // set rk and ckr
        this.RK = KDF_RK_OUT.rk;
        this.CKr = KDF_RK_OUT.ck;
        // get a new DH
        this.DHs = doubleRatchetFunctions.GENERATE_DH();
        // calculate KDF_RK
        KDF_RK_OUT = doubleRatchetFunctions.KDF_RK(this.RK, doubleRatchetFunctions.DH(this.DHs, this.DHr));
        // set rk and cks
        this.RK = KDF_RK_OUT.rk;
        this.CKs = KDF_RK_OUT.ck;
    }

    // decrypt function
    async decrypt(message) {
        // try skipped message keys
        let plaintext = this.TrySkippedMessageKeys(message.header, message.ciphertext);
        // check if we have plaintext
        if (plaintext !== false) {
            return {
                cleartext: plaintext
            };
        }
        // if the header's dh isn't our DHr
        if (this.DHr === null || message.header.dh !== _crypto.util.encodeBase64(this.DHr)) {
            // skip skip skip
            this.SkipMessageKeys(message.header.pn);
            // ratchet ratchet rachet
            this.DHRatchet(message.header);
        }
        // skip message keys
        // im so tired christ
        this.SkipMessageKeys(message.header.n);
        // SET THEM SET THEM SET THEM
        let KDF_CK_OUTPUT = doubleRatchetFunctions.KDF_CK(this.CKr);
        // set CKr and MK
        this.CKr = KDF_CK_OUTPUT.ck;
        let mk = KDF_CK_OUTPUT.mk;
        // inc Nr
        this.Nr++;
        return {
            cleartext: doubleRatchetFunctions.DECRYPT(mk, message.ciphertext, doubleRatchetFunctions.CONCAT(message.header))
        };
    }

    // export function
    export() {
        let exports = {};
        for (let key of Object.keys(doubleRatchetFunctions.types)) {
            if (this[key] !== undefined) {
                let type = doubleRatchetFunctions.types[key];
                if (type === "nBuf") {
                    exports[key] = this[key];
                }
                else if (type === "buf") {
                    exports[key] = _crypto.util.encodeBase64(this[key]);
                }
                else if (type === "key") {
                    exports[key] = {
                        publicKey: _crypto.util.encodeBase64(this[key].publicKey),
                        secretKey: _crypto.util.encodeBase64(this[key].secretKey)
                    }
                }
                else if (type === "MKSKIPPED") {
                    let base64MKSKIPPED = this[key];
                    for (let mkSkippedKey of Object.keys(base64MKSKIPPED)) {
                        for (let secondSkippedKey of Object.keys(base64MKSKIPPED[mkSkippedKey])) {
                            base64MKSKIPPED[mkSkippedKey][secondSkippedKey] = _crypto.util.encodeBase64(base64MKSKIPPED[mkSkippedKey][secondSkippedKey]);
                        }
                    }
                    exports[key] = base64MKSKIPPED;
                }
            }
        }
        return exports;
    }
};

window.secretSession = doubleRatchet;

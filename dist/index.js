"use strict";
/**
 * This code originated from counterwallet/lib/util.bitcore.js
 */
Object.defineProperty(exports, "__esModule", { value: true });
const bitcore = require("bitcore-lib");
const base58 = require("bs58");
const crypto = require("crypto");
class Base58Checksum {
    constructor(params) {
        this.params = params;
        this.version = new Buffer([bitcore.Networks.livenet.pubkeyhash]);
        this.private_key_version = new Buffer([0x80]);
        this.checksumPad = new Buffer([0, 0, 0, 0]);
        if (!params)
            return;
        // private-key-version
        if (params.private_key_version)
            this.private_key_version = new Buffer(params.private_key_version, 'hex');
        if (params.address_pubkeyhash_version)
            this.version = new Buffer(params.address_pubkeyhash_version, 'hex');
        if (params.address_checksum_value)
            this.checksumPad = new Buffer(params.address_checksum_value, 'hex');
        if (params['private-key-version'])
            this.private_key_version = new Buffer(params['private-key-version'], 'hex');
        if (params['address-pubkeyhash-version'])
            this.version = new Buffer(params['address-pubkeyhash-version'], 'hex');
        if (params['address-checksum-value'])
            this.checksumPad = new Buffer(params['address-checksum-value'], 'hex');
    }
    ripemd160(msg) {
        return crypto.createHash("ripemd160").update(msg).digest();
    }
    sha256(msg) {
        return crypto.createHash("sha256").update(msg).digest();
    }
    sha256sha256(msg) {
        return this.sha256(this.sha256(msg));
    }
    sha256ripemd160(msg) {
        return this.ripemd160(this.sha256(msg));
    }
    // Encode a buffer as a base58-check encoded string
    encode(payload) {
        var checksum = this.sha256sha256(payload);
        checksum = new Buffer([
            checksum[0] ^ this.checksumPad[0],
            checksum[1] ^ this.checksumPad[1],
            checksum[2] ^ this.checksumPad[2],
            checksum[3] ^ this.checksumPad[3],
        ]);
        // console.log('new checksum: ', checksum.toString('hex'));
        return base58.encode(Buffer.concat([
            payload,
            checksum
        ], payload.length + 4));
    }
    decodeRaw(buffer) {
        let payload = buffer.slice(0, -4);
        let checksum = buffer.slice(-4);
        let newChecksum = this.sha256sha256(payload);
        checksum = new Buffer([
            checksum[0] ^ this.checksumPad[0],
            checksum[1] ^ this.checksumPad[1],
            checksum[2] ^ this.checksumPad[2],
            checksum[3] ^ this.checksumPad[3],
        ]);
        if (checksum[0] ^ newChecksum[0] |
            checksum[1] ^ newChecksum[1] |
            checksum[2] ^ newChecksum[2] |
            checksum[3] ^ newChecksum[3])
            return;
        return payload;
    }
    // Decode a base58-check encoded string to a buffer, no result if checksum is wrong
    decodeUnsafe(string) {
        var buffer = base58.decodeUnsafe(string);
        if (!buffer)
            return;
        return this.decodeRaw(buffer);
    }
    decode(string) {
        var buffer = base58.decode(string);
        var payload = this.decodeRaw(buffer);
        if (!payload)
            throw new Error('Invalid checksum');
        return payload;
    }
    getAddress(privkeypair, compressed = true) {
        return this.getAddressFromPublicKey(new Buffer(privkeypair.getPublic().encode(16, compressed)));
    }
    isValidAddress(address) {
        try {
            this.getHashFromAddress(address);
            return true;
        }
        catch (err) {
            return false;
        }
    }
    getAddressFromPublicKey(pubkeybuf) {
        pubkeybuf = (typeof (pubkeybuf) === 'string') ? new Buffer(pubkeybuf, 'hex') : pubkeybuf;
        var hashBuffer = this.sha256ripemd160(pubkeybuf);
        return this.getAddressFromHash(hashBuffer);
    }
    getAddressFromHash(hashBuffer) {
        let versionArray = [...this.version];
        let hashArray = [...hashBuffer];
        let spacing = Math.floor(20 / versionArray.length);
        let versionedArray = [];
        let j = 0;
        for (var i = 0; i < hashArray.length; i++) {
            if (i === spacing * j) {
                versionedArray.push(versionArray[j]);
                j++;
            }
            versionedArray.push(hashArray[i]);
        }
        let versionedBuffer = new Buffer(versionedArray);
        return this.encode(versionedBuffer);
    }
    getHashFromAddress(address) {
        let versionedBuffer = this.decode(address);
        // console.log('versionedBuffer: '+versionedBuffer.toString('hex'));
        let versionedArray = [...versionedBuffer];
        let versionArray = [...this.version];
        let spacing = Math.floor(20 / versionArray.length);
        let hashArray = [];
        let version = [];
        let j = 0;
        for (var i = 0; i < versionedArray.length; i++) {
            if (i === (spacing + 1) * j && j < versionArray.length) {
                version.push(versionedArray[i]);
                j++;
                continue;
            }
            hashArray.push(versionedArray[i]);
        }
        let versionBuf = new Buffer(version);
        // console.log('chain: '+this.version.toString('hex'));
        // console.log('read : '+versionBuf.toString('hex'));
        if (!this.version.equals(versionBuf)) {
            throw new Error('Version mismatch: ' + this.version.toString('hex')
                + ':' + versionBuf.toString('hex'));
        }
        return new Buffer(hashArray);
    }
    encodePrivateKey(privateKey, compressed = true) {
        return this.encodeKey(privateKey, compressed);
    }
    encodePublicKey(pubkeybuf, compressed = true) {
        return this.encodeKey(pubkeybuf, compressed);
    }
    encodeKey(key, compressed = true) {
        let keybuf = (typeof (key) === 'string') ? new Buffer(key, 'hex') : key;
        if (compressed) {
            keybuf = Buffer.concat([keybuf, new Buffer([0x01])], keybuf.length + 1);
        }
        keybuf = (typeof (keybuf) === 'string') ? new Buffer(keybuf, 'hex') : keybuf;
        // var pubkeybuf = new Buffer(privkeypair.getPublic().encode(16, compressed));
        // console.log('pubkeybuf: '+ keybuf.toString('hex'));
        // console.log('pubkeybuf.length: '+ keybuf.length);
        let versionArray = [...this.private_key_version];
        let privArray = [...keybuf];
        let spacing = Math.floor(33 / versionArray.length);
        let versionedArray = [];
        let j = 0;
        for (var i = 0; i < privArray.length; i++) {
            if (i === spacing * j && j < versionArray.length) {
                versionedArray.push(versionArray[j]);
                j++;
            }
            versionedArray.push(privArray[i]);
        }
        let versionedBuffer = new Buffer(versionedArray);
        return this.encode(versionedBuffer);
    }
    decodeKey(keyAddress) {
        let versionedBuffer = this.decode(keyAddress);
        // console.log('vbuf: '+ versionedBuffer.toString('hex'));
        let versionedArray = [...versionedBuffer];
        let versionArray = [...this.private_key_version];
        let spacing = Math.floor(33 / versionArray.length);
        let hashArray = [];
        let version = [];
        let j = 0;
        for (var i = 0; i < versionedArray.length; i++) {
            if (i === (spacing + 1) * j) {
                // if(j < versionArray.length)
                version.push(versionedArray[i]);
                if (j < (versionArray.length - 1))
                    j++;
                continue;
            }
            hashArray.push(versionedArray[i]);
        }
        let versionBuf = new Buffer(version);
        if (!this.private_key_version.equals(versionBuf)) {
            throw new Error('Version mismatch: ' + this.private_key_version.toString('hex')
                + ':' + versionBuf.toString('hex'));
        }
        return new Buffer(hashArray).slice(0, -1);
    }
}
exports.Base58Checksum = Base58Checksum;

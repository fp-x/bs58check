/**
 * This code originated from counterwallet/lib/util.bitcore.js
 */

import * as bitcore from 'bitcore-lib';
import * as base58 from 'bs58';
import * as crypto from 'crypto';

export class Base58Checksum {

	version: any = new Buffer([bitcore.Networks.livenet.pubkeyhash]);
	private_key_version: any = new Buffer([0x80]);
	checksumPad: Buffer = new Buffer([0,0,0,0]);
	constructor(public params?) {
		if(!params) return;

		// private-key-version
		if(params.private_key_version)
			this.private_key_version = new Buffer(params.private_key_version, 'hex');
		if(params.address_pubkeyhash_version)
			this.version = new Buffer(params.address_pubkeyhash_version, 'hex');
		if(params.address_checksum_value)
			this.checksumPad = new Buffer(params.address_checksum_value, 'hex');
		if(params['private-key-version'])
			this.private_key_version = new Buffer(params['private-key-version'], 'hex');
		if(params['address-pubkeyhash-version'])
			this.version = new Buffer(params['address-pubkeyhash-version'], 'hex');
		if(params['address-checksum-value'])
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
		console.log('new checksum: ', checksum.toString('hex'));

		return base58.encode(Buffer.concat([
			payload,
			checksum
		], payload.length + 4))
	}

	private decodeRaw(buffer) {
		let payload = buffer.slice(0, -4)
		let checksum = buffer.slice(-4)
		let newChecksum = this.sha256sha256(payload)

		checksum = new Buffer([
			checksum[0] ^ this.checksumPad[0],
			checksum[1] ^ this.checksumPad[1],
			checksum[2] ^ this.checksumPad[2],
			checksum[3] ^ this.checksumPad[3],
			]);

		if (checksum[0] ^ newChecksum[0] |
			checksum[1] ^ newChecksum[1] |
			checksum[2] ^ newChecksum[2] |
			checksum[3] ^ newChecksum[3]) return

		return payload
	}

	// Decode a base58-check encoded string to a buffer, no result if checksum is wrong
	decodeUnsafe(string) {
		var buffer = base58.decodeUnsafe(string)
		if (!buffer) return

		return this.decodeRaw(buffer)
	}

	decode(string) {
		var buffer = base58.decode(string)
		var payload = this.decodeRaw(buffer)
		if (!payload) throw new Error('Invalid checksum')
		return payload
	}
	getAddress(privkeypair, compressed: boolean = true) {
		var pubkeybuf = new Buffer(privkeypair.getPublic().encode(16, compressed));
		var hashBuffer = this.sha256ripemd160(pubkeybuf);
		return this.getAddressFromHash(hashBuffer);
	}
	getAddressFromHash(hashBuffer: any) {

		let versionArray = [...this.version];
		let hashArray = [...hashBuffer];
		let spacing = Math.floor(20/versionArray.length);

		let versionedArray = [];
		let j = 0;
		for(var i = 0; i < hashArray.length; i++) {
			if(i === spacing*j) {
				versionedArray.push(versionArray[j]);
				j++;
			}
			versionedArray.push(hashArray[i]);
		}
		let versionedBuffer = new Buffer(versionedArray);

		return this.encode(versionedBuffer);
	}

	encodePrivateKey(privateKey:string|Buffer, compressed=true) {
		let priv: Buffer = (typeof(privateKey) === 'string')? new Buffer(privateKey, 'hex') : privateKey;

		if(compressed) {
			priv = Buffer.concat([ priv, new Buffer([0x01]) ], priv.length + 1)
		}
		let versionArray = [...this.private_key_version];
		let privArray = [...priv];
		let spacing = Math.floor(33/versionArray.length);
		let versionedArray = [];
		let j = 0;
		for(var i = 0; i < privArray.length; i++) {
			if(i === spacing*j && j < versionArray.length) {
				versionedArray.push(versionArray[j]);
				j++;
			}
			versionedArray.push(privArray[i]);
		}
		let versionedBuffer = new Buffer(versionedArray);
		return this.encode(versionedBuffer);
	}
}


import * as mocha from 'mocha';
import * as chai from 'chai';

import { Base58Checksum } from '../src/index';

import {fixtures} from './fixtures';
const expect = chai.expect;

const passphrase1 = 'mansion index trip little finish cash expect depart fantasy oven expire manage';

describe('Address Base58Checksum multichain', () => {

	it("should create a bitcoin compatible passphrase", () => {
		const bs58 = new Base58Checksum();
		fixtures.valid.forEach((f) => {

				var actual = bs58.decode(f.string).toString('hex')
				expect(actual).to.equal(f.payload);

				actual = bs58.decodeUnsafe(f.string).toString('hex')
				expect(actual).to.equal(f.payload);
		});
	});

	it("should reject a non-multichain compatible address", () => {
		// https://www.multichain.com/developers/address-key-format/
		const multichainSampleParams = {address_pubkeyhash_version: '00AFEA21', address_checksum_value: '953ABC69'};
		const bs58 = new Base58Checksum(multichainSampleParams);
		fixtures.valid.forEach((f) => {
				expect(() => bs58.decode(f.string)).to.throw(/Invalid checksum/); // from bitcoin test
		});
	});
});

describe('Private key - Base58Checksum multichain', () => {

	// Start with a raw private ECDSA key:
	// 	B69CA8FFAE36F11AD445625E35BF6AC57D6642DDBE470DD3E7934291B2000D78
	// Add 0x01 at the end if this private key corresponds to a compressed public key:
	// 	B69CA8FFAE36F11AD445625E35BF6AC57D6642DDBE470DD3E7934291B2000D7801
	// Different from bitcoin: Add the first version byte from the private-key-version blockchain 
	// parameter to the start of the private key. If it is more than one byte long, insert each subsequent 
	// byte of it after every floor(33/len(private-key-version)) bytes of the key. For example with 8025B89E:
	// 	80B69CA8FFAE36F11A25D445625E35BF6AC5B87D6642DDBE470DD39EE7934291B2000D7801
	// Calculate the SHA-256 of the extended private key:
	// 	742D5B3C59BB25F077AACB33D5770AAE22FD5639E8F9A7742BADEF84BCDFB4CC
	// Calculate the SHA-256 hash of the previous SHA-256 hash:
	// 	4FBB9708A0B5F2F5AC384CAC22C69CCE3F7DCE6166DE63B5AFE35E5D59767F18
	// Take the first 4 bytes of the most recent SHA-256 hash. This is the address checksum:
	// 	4FBB9708
	// Different from bitcoin: XOR this checksum with the address-checksum-value blockchain parameter. For example with 7B7AEF76:
	// 	34C1787E
	// Add the 4-byte checksum (after XORing) at the end of extended extended private key. This is the 41-byte (for a 4-byte version) key:
	// 	80B69CA8FFAE36F11A25D445625E35BF6AC5B87D6642DDBE470DD39EE7934291B2000D780134C1787E
	// Convert the result to a string using bitcoin base58 encoding. This gives the commonly used private key format:
	// 	VEEWgYhDhqWnNnDCXXjirJYXGDFPjH1B8v6hmcnj1kLXrkpxArmz7xXw
	it("should match multichain's instructions", () => {
		// https://www.multichain.com/developers/address-key-format/
		const multichainSampleParams = {private_key_version: '8025B89E', address_checksum_value: '7B7AEF76'};
		const bs58 = new Base58Checksum(multichainSampleParams);

		let key = bs58.encodePrivateKey('B69CA8FFAE36F11AD445625E35BF6AC57D6642DDBE470DD3E7934291B2000D78');
		expect(key).to.equal('VEEWgYhDhqWnNnDCXXjirJYXGDFPjH1B8v6hmcnj1kLXrkpxArmz7xXw');
	});



	it("should work for real", () => {
		const multichainSampleParams = {private_key_version: '809c1407', address_checksum_value: '45971f16'};
		const bs58 = new Base58Checksum(multichainSampleParams);

		let key = bs58.encodePrivateKey('c88b948e898d802f6b75ad26e00ecd9e26442e04b1e30d456700b6ba76ca4b45');
		console.log('encoded key: '+key);
		expect(key).not.to.equal('VEEWgYhDhqWnNnDCXXjirJYXGDFPjH1B8v6hmcnj1kLXrkpxArmz7xXw');
	});


});


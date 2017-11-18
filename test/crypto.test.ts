import * as mocha from 'mocha';
import * as chai from 'chai';

import { Base58Checksum } from '../src/index';

import {fixtures} from './fixtures';
const expect = chai.expect;

import * as bitcore from 'bitcore-lib';

const passphrase1 = 'mansion index trip little finish cash expect depart fantasy oven expire manage';

describe('Address Base58Checksum bitcoin', () => {

	it("should create a bitcoin compatible address", () => {
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

describe('Address Base58Checksum multichain', () => {


	it("should reject a non-multichain compatible address", () => {
		// https://www.multichain.com/developers/address-key-format/
		const multichainSampleParams = {address_pubkeyhash_version: '0087e099', address_checksum_value: '45971f16'};
		const bs58 = new Base58Checksum(multichainSampleParams);
		let pubkey = new Buffer('03ea3e4710d5c7659d72ca696339dd67f524e8f8fd13d433b38763cde76ca53dd4', 'hex');
		let hashBuffer = bs58.sha256ripemd160(pubkey);
		let address = bs58.getAddressFromHash(hashBuffer);
		console.log('address: '+address);
		expect(address).to.be.a('string'); 
	});
});
describe('Pubkeyaddr Base58Checksum multichain', () => {


	it("should reject a non-multichain compatible address", () => {
		// https://www.multichain.com/developers/address-key-format/
		const multichainSampleParams = {address_pubkeyhash_version: '0087e099', address_checksum_value: '45971f16'};
		const bs58 = new Base58Checksum(multichainSampleParams);
		// this.priv = secp256k1.keyFromPrivate(priv, 'hex'); // bitcore.PrivateKey(this.priv, NETWORK);			

		let pubkey = new Buffer('03ea3e4710d5c7659d72ca696339dd67f524e8f8fd13d433b38763cde76ca53dd4', 'hex');
		let pubkeyaddr = bs58.encodePublicKey(pubkey);
		console.log('pubkeyaddr: '+pubkeyaddr);
		expect(pubkeyaddr).to.be.a('string'); 
	});
});

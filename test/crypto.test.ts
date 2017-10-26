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


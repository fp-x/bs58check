/// <reference types="node" />
export declare class Base58Checksum {
    params: any;
    version: any;
    private_key_version: any;
    checksumPad: Buffer;
    constructor(params?: any);
    ripemd160(msg: any): Buffer;
    sha256(msg: any): Buffer;
    sha256sha256(msg: any): Buffer;
    sha256ripemd160(msg: any): Buffer;
    encode(payload: any): any;
    private decodeRaw(buffer);
    decodeUnsafe(string: any): any;
    decode(string: any): any;
    getAddress(privkeypair: any, compressed?: boolean): any;
    isValidAddress(address: string): boolean;
    getAddressFromPublicKey(pubkeybuf: string | Buffer): any;
    getAddressFromHash(hashBuffer: any): any;
    getHashFromAddress(address: string): Buffer;
    encodePrivateKey(privateKey: string | Buffer, compressed?: boolean): any;
    encodePublicKey(pubkeybuf: string | Buffer, compressed?: boolean): any;
    encodeKey(key: string | Buffer, compressed?: boolean): any;
    decodeKey(keyAddress: string): Buffer;
}

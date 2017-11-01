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
    getAddressFromHash(hashBuffer: any): any;
    encodePrivateKey(priv: string | Buffer, compressed?: boolean): any;
}

import assert from 'node:assert/strict';
import test from 'node:test';
import { der, oid, seq, set } from './core.mjs';
import { sameDistinguishedName } from './x509-name.mjs';

const attr = (id, tag, value) => seq(oid(id), der(tag, Buffer.from(value)));
const name = (...rdns) => seq(...rdns.map((attributes) => set(...attributes)));
const cn = (tag, value) => attr('2.5.4.3', tag, value);
const org = (value) => attr('2.5.4.10', 0x0c, value);

test('RFC 5280 issuer equality handles case, UTF8/Printable and LDAP insignificant spaces', () => {
  const left = name([cn(0x13, '  Labs   Signer  ')]);
  const right = name([cn(0x0c, 'labs signer')]);
  assert.equal(sameDistinguishedName(left, right), true);
  assert.equal(sameDistinguishedName(name([cn(0x0c, 'Straße')]), name([cn(0x0c, 'STRASSE')])), true);
  assert.equal(sameDistinguishedName(name([cn(0x0c, 'A\u00a0B')]), name([cn(0x0c, 'a b')])), true);
});

test('issuer equality preserves RDN order and all naming attributes', () => {
  const a = name([cn(0x0c, 'Labs'), org('Example')], [cn(0x0c, 'Signer')]);
  const b = name([org('example'), cn(0x13, 'labs')], [cn(0x0c, 'signer')]);
  assert.equal(sameDistinguishedName(a, b), true);
  assert.equal(sameDistinguishedName(a, name([cn(0x0c, 'Signer')], [org('Example'), cn(0x0c, 'Labs')])), false);
  assert.equal(sameDistinguishedName(a, name([cn(0x0c, 'Labs')], [cn(0x0c, 'Signer')])), false);
  assert.equal(sameDistinguishedName(a, name([cn(0x0c, 'Mabs'), org('Example')], [cn(0x0c, 'Signer')])), false);
});

test('domainComponent uses case-insensitive exact IA5 label matching', () => {
  const dc = (value) => attr('0.9.2342.19200300.100.1.25', 0x16, value);
  assert.equal(sameDistinguishedName(name([dc('EXAMPLE')]), name([dc('example')])), true);
  assert.equal(sameDistinguishedName(name([dc('example')]), name([dc('example.com')])), false);
});

test('unknown matching rules stay exact and malformed text cannot be equated', () => {
  const unknown = (value) => attr('1.3.6.1.4.1.55555.9.99', 0x0c, value);
  assert.equal(sameDistinguishedName(name([unknown('Labs')]), name([unknown('labs')])), false);
  assert.throws(() => sameDistinguishedName(name([cn(0x0c, Buffer.from([0xff]))]), name([cn(0x0c, 'x')])),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
  assert.throws(() => sameDistinguishedName(name([cn(0x0c, '\u0221')]), name([cn(0x0c, '\u0221')])),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
  assert.throws(() => sameDistinguishedName(name([cn(0x0c, '\ue000')]), name([cn(0x0c, '\ue000')])),
    { code: 'CADES_ISSUER_NAME_ENCODING' });
});

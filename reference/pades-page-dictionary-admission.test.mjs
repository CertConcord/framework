import assert from 'node:assert/strict';
import test, { before, after } from 'node:test';
import {
  padesFixture, independentApproval, plainPDF, appendRevision, decision, loadPAdES,
} from './pades-fixtures.mjs';

const api = await loadPAdES();
let fixture;
before(() => { fixture = padesFixture(); });
after(() => fixture?.close());

const page = ({ parent = '/Parent 2 0 R', media = '/MediaBox [0 0 300 200]',
  resources = '/Resources << /Font << /F1 4 0 R >> >>', rotate = '',
  contents = '/Contents 5 0 R' } = {}) =>
  `<< /Type /Page ${parent} ${media} ${resources} ${rotate} ${contents} >>`;
const pages = (extra = '') => `<< /Type /Pages /Kids [3 0 R] /Count 1 ${extra} >>`;
const signedDecision = async (pdf, overall, reason) => {
  const signed = independentApproval(fixture, { pdf }).pdf;
  const actual = await decision(api, fixture, signed);
  assert.equal(actual.overall, overall, JSON.stringify(actual));
  assert.equal(actual.reason, reason);
};

test('signed Page Rotate accepts local and inherited integer multiples of 90', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ rotate: '/Rotate 90' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/Rotate 270') },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ rotate: '/Rotate -90' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ rotate: '/Rotate null' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/Rotate null') },
  ]), 'VALID', 'PADES_VALID');
});

test('signed Page Rotate rejects an array and a non-multiple of 90', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ rotate: '/Rotate []' }) },
  ]), 'INVALID', 'PADES_PAGE_ROTATE');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/Rotate 45') },
  ]), 'INVALID', 'PADES_PAGE_ROTATE');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ rotate: '/Rotate 90.0' }) },
  ]), 'INVALID', 'PADES_PAGE_ROTATE');
});

test('signed Page Parent binds to the immediate containing Pages node', async () => {
  await signedDecision(plainPDF(), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ parent: '' }) },
  ]), 'INVALID', 'PADES_PAGE_PARENT');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ parent: '/Parent 4 0 R' }) },
  ]), 'INVALID', 'PADES_PAGE_PARENT');
});

test('signed Page MediaBox accepts local and inherited four-number rectangles', async () => {
  await signedDecision(plainPDF(), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/MediaBox [0 0 300 200]') },
    { number: 3, body: page({ media: '' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ media: '/MediaBox [300 200 0 0]' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/MediaBox [0 0 300 200]') },
    { number: 3, body: page({ media: '/MediaBox null' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/MediaBox null') },
  ]), 'VALID', 'PADES_VALID');
});

test('signed Page MediaBox rejects missing or malformed effective rectangles', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ media: '' }) },
  ]), 'INVALID', 'PADES_PAGE_MEDIABOX');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ media: '/MediaBox [0 0 300]' }) },
  ]), 'INVALID', 'PADES_PAGE_MEDIABOX');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ media: '/MediaBox [0 0 true 200]' }) },
  ]), 'INVALID', 'PADES_PAGE_MEDIABOX');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ media: '/MediaBox null' }) },
  ]), 'INVALID', 'PADES_PAGE_MEDIABOX');
});

test('signed Page Resources must resolve even without text operators', async () => {
  const noResources = plainPDF({ stream: 'q Q\n' });
  await signedDecision(appendRevision(noResources, [
    { number: 3, body: page({ resources: '/Resources << >>' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(noResources, [
    { number: 2, body: pages('/Resources << >>') },
    { number: 3, body: page({ resources: '' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(noResources, [
    { number: 3, body: page({ resources: '' }) },
  ]), 'INVALID', 'PADES_PAGE_RESOURCES');
  await signedDecision(appendRevision(noResources, [
    { number: 2, body: pages('/Resources << >>') },
    { number: 3, body: page({ resources: '/Resources null' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(noResources, [
    { number: 2, body: pages('/Resources null') },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(noResources, [
    { number: 3, body: page({ resources: '/Resources null' }) },
  ]), 'INVALID', 'PADES_PAGE_RESOURCES');
});

test('signed Pages Count matches its descendant leaves', async () => {
  await signedDecision(plainPDF(), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: '<< /Type /Pages /Kids [3 0 R] /Count 2 >>' },
  ]), 'INVALID', 'PADES_PAGE_TREE_COUNT');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: '<< /Type /Pages /Kids [3 0 R] /Count 1.0 >>' },
  ]), 'INVALID', 'PADES_PAGE_TREE_COUNT');
});

test('signed root Pages prohibits Parent and nested Pages binds its parent', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: '<< /Type /Pages /Kids [6 0 R] /Count 1 >>' },
    { number: 6, body: '<< /Type /Pages /Parent 2 0 R /Kids [3 0 R] /Count 1 >>' },
    { number: 3, body: page({ parent: '/Parent 6 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: '<< /Type /Pages /Kids [3 0 R] /Count 1 /Parent 4 0 R >>' },
  ]), 'INVALID', 'PADES_PAGE_TREE_PARENT');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: '<< /Type /Pages /Kids [3 0 R] /Count 1 /Parent null >>' },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: '<< /Type /Pages /Kids [6 0 R] /Count 1 >>' },
    { number: 6, body: '<< /Type /Pages /Parent 4 0 R /Kids [3 0 R] /Count 1 >>' },
    { number: 3, body: page({ parent: '/Parent 6 0 R' }) },
  ]), 'INVALID', 'PADES_PAGE_TREE_PARENT');
});

test('signed indirect null Rotate and root Parent are omitted', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 6, body: 'null' },
    { number: 3, body: page({ rotate: '/Rotate 6 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 6, body: 'null' },
    { number: 2, body: pages('/Rotate 6 0 R /Parent 6 0 R') },
  ]), 'VALID', 'PADES_VALID');
});

test('signed indirect null MediaBox inherits or fails when no effective rectangle exists', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 6, body: 'null' },
    { number: 2, body: pages('/MediaBox [0 0 300 200]') },
    { number: 3, body: page({ media: '/MediaBox 6 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 6, body: 'null' },
    { number: 3, body: page({ media: '/MediaBox 6 0 R' }) },
  ]), 'INVALID', 'PADES_PAGE_MEDIABOX');
});

test('signed indirect null Resources inherits or fails when no effective dictionary exists', async () => {
  const noText = plainPDF({ stream: 'q Q\n' });
  await signedDecision(appendRevision(noText, [
    { number: 6, body: 'null' },
    { number: 2, body: pages('/Resources << >>') },
    { number: 3, body: page({ resources: '/Resources 6 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(noText, [
    { number: 6, body: 'null' },
    { number: 3, body: page({ resources: '/Resources 6 0 R' }) },
  ]), 'INVALID', 'PADES_PAGE_RESOURCES');
});

test('signed undefined indirect Rotate and root Parent are omitted', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ rotate: '/Rotate 99 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/Parent 99 0 R') },
  ]), 'VALID', 'PADES_VALID');
});

test('signed undefined indirect MediaBox inherits or fails without an effective rectangle', async () => {
  await signedDecision(appendRevision(plainPDF(), [
    { number: 2, body: pages('/MediaBox [0 0 300 200]') },
    { number: 3, body: page({ media: '/MediaBox 99 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(plainPDF(), [
    { number: 3, body: page({ media: '/MediaBox 99 0 R' }) },
  ]), 'INVALID', 'PADES_PAGE_MEDIABOX');
});

test('signed undefined indirect Resources inherits or fails without an effective dictionary', async () => {
  const noText = plainPDF({ stream: 'q Q\n' });
  await signedDecision(appendRevision(noText, [
    { number: 2, body: pages('/Resources << >>') },
    { number: 3, body: page({ resources: '/Resources 99 0 R' }) },
  ]), 'VALID', 'PADES_VALID');
  await signedDecision(appendRevision(noText, [
    { number: 3, body: page({ resources: '/Resources 99 0 R' }) },
  ]), 'INVALID', 'PADES_PAGE_RESOURCES');
});

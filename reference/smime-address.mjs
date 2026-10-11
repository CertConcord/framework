import addressparser from 'nodemailer/lib/addressparser';
import { check } from './smime-adapter-common.mjs';

// Selected ASCII dot-atom mailboxes. The mature parser is also required to
// consume the exact address; its error recovery never creates an identity.
export function normalizeMailbox({ mailbox } = {}) {
  check(typeof mailbox === 'string' && mailbox.length <= 1024, 'SMIME_MAILBOX_INPUT');
  check(!/[^\x00-\x7f]/.test(mailbox), 'SMIME_EAI_UNSUPPORTED', 'UNSUPPORTED');
  check(!/[\x00-\x1f\x7f]/.test(mailbox), 'SMIME_MAILBOX_SYNTAX');
  if (
    /^"(?:[^"\\\r\n]|\\[\x20-\x7e])*"@[A-Za-z0-9.-]+$/.test(mailbox) ||
    /^[^@\s]+@\[[^\[\]\r\n]+\]$/.test(mailbox)
  )
    check(false, 'SMIME_MAILBOX_GRAMMAR_UNSUPPORTED', 'UNSUPPORTED');
  if (/[<>,:;]/.test(mailbox)) {
    const values = addressparser(mailbox);
    check(values.length > 0, 'SMIME_MAILBOX_SYNTAX');
    // Accept no recovered tail when identifying a legal but unselected list.
    const parts = [];
    let quoted = false,
      escaped = false,
      angle = 0,
      group = 0,
      start = 0;
    for (let i = 0; i < mailbox.length; i++) {
      const c = mailbox[i];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (quoted && c === '\\') {
        escaped = true;
        continue;
      }
      if (c === '"') {
        quoted = !quoted;
        continue;
      }
      if (quoted) continue;
      if (c === '<') angle++;
      if (c === '>') angle--;
      check(angle >= 0 && angle <= 1, 'SMIME_MAILBOX_SYNTAX');
      if (!angle && c === ':') {
        check(group === 0, 'SMIME_MAILBOX_SYNTAX');
        group = 1;
      }
      if (!angle && c === ';') {
        check(group === 1, 'SMIME_MAILBOX_SYNTAX');
        group = 0;
      }
      if (!angle && !group && c === ',') {
        parts.push(mailbox.slice(start, i).trim());
        start = i + 1;
      }
    }
    check(!quoted && !escaped && angle === 0 && group === 0, 'SMIME_MAILBOX_SYNTAX');
    parts.push(mailbox.slice(start).trim());
    for (const part of parts) {
      const groupMatch = /^([^<>:;,]+):([^:;]*);$/.exec(part);
      if (groupMatch) {
        for (const member of groupMatch[2]
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean))
          headerMailbox(member);
      } else headerMailbox(part);
    }
    check(false, 'SMIME_MAILBOX_GRAMMAR_UNSUPPORTED', 'UNSUPPORTED');
  }
  check(!/\s/.test(mailbox), 'SMIME_MAILBOX_SYNTAX');
  const at = mailbox.indexOf('@');
  check(at > 0 && at === mailbox.lastIndexOf('@'), 'SMIME_MAILBOX_SYNTAX');
  const local = mailbox.slice(0, at),
    domain = mailbox.slice(at + 1);
  check(
    /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/.test(local) &&
      domain.length > 0 &&
      domain.split('.').every((part) => /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(part)),
    'SMIME_MAILBOX_SYNTAX',
  );
  const parsed = addressparser(mailbox);
  check(
    parsed.length === 1 && !parsed[0].group && !parsed[0].name && parsed[0].address === mailbox,
    'SMIME_MAILBOX_SYNTAX',
  );
  return { mailbox: `${local}@${domain.toLowerCase()}` };
}

export function headerMailbox(value) {
  check(typeof value === 'string' && value.length <= 1024, 'SMIME_MAILBOX_HEADER');
  let quote = false,
    escape = false,
    left = -1,
    right = -1;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (escape) {
      escape = false;
      continue;
    }
    if (quote && c === '\\') {
      escape = true;
      continue;
    }
    if (c === '"') {
      quote = !quote;
      continue;
    }
    if (quote) continue;
    check(!'():;,'.includes(c), 'SMIME_MAILBOX_HEADER');
    if (c === '<') {
      check(left < 0, 'SMIME_MAILBOX_HEADER');
      left = i;
    }
    if (c === '>') {
      check(left >= 0 && right < 0, 'SMIME_MAILBOX_HEADER');
      right = i;
    }
  }
  check(!quote && !escape && left < 0 === right < 0, 'SMIME_MAILBOX_HEADER');
  if (left >= 0) check(value.slice(right + 1).trim() === '', 'SMIME_MAILBOX_HEADER');
  const addr = left < 0 ? value.trim() : value.slice(left + 1, right);
  const normalized = normalizeMailbox({ mailbox: addr }).mailbox;
  const parsed = addressparser(value);
  check(
    parsed.length === 1 && !parsed[0].group && parsed[0].address === addr,
    'SMIME_MAILBOX_HEADER',
  );
  return normalized;
}

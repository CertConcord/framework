import {
  normalizeMailbox,
  prepareMimeMessage,
  parseProtectedMessage,
  packageCMS,
  inspectVerifiedMime,
} from './smime-mime.mjs';
import { createSmimeCMS } from './smime-cms.mjs';

/** Local, bounded MIME/CMS machinery. Trust and mailbox decisions belong to the application. */
export function createSmimeBackend(configuration) {
  const cms = createSmimeCMS(configuration);
  return Object.freeze({
    normalizeMailbox,
    prepareMimeMessage,
    parseProtectedMessage,
    packageCMS,
    inspectVerifiedMime,
    ...cms,
  });
}

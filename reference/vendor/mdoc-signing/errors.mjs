export class MdocValidationError extends Error {
  constructor(code, overall = 'INVALID') {
    super(code);
    this.code = code;
    this.overall = overall;
  }
}
export function requireThat(condition, code, overall = 'INVALID') {
  if (!condition) throw new MdocValidationError(code, overall);
}

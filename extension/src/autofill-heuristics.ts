export type AutofillFieldKind = "username" | "password" | "otp";

export interface DiscoveredAutofillFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  otp: HTMLInputElement[];
}

const USERNAME_HINTS = /(?:user(?:name|id)?|login|sign\s*in|email|e-?mail|account|customer|member|identifier|ユーザー|メール|アカウント)/iu;
const PASSWORD_HINTS = /(?:pass(?:word|wd|wort|code)?|secret|credential|パスワード|暗証)/iu;
const OTP_HINTS = /(?:one[ -]?time|otp|totp|mfa|2fa|two[ -]?factor|verification|security|auth(?:entication)?|passcode|pin|code|token|認証|確認|ワンタイム|コード)/iu;
const NUMERIC_PATTERN = /\d/u;
const INPUT_SELECTOR = "input";

/**
 * Returns visible, editable inputs only. The content script intentionally keeps
 * this input-only: filling textareas or contenteditable nodes is much more
 * likely to corrupt unrelated page content than to improve login coverage.
 */
export function isFillableInput(input: HTMLInputElement): boolean {
  if (input.disabled || input.readOnly || input.type === "hidden") return false;
  const rect = input.getBoundingClientRect();
  const style = getComputedStyle(input);
  return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
}

/** Classifies a field using autocomplete, input attributes, and nearby labels. */
export function classifyAutofillInput(input: HTMLInputElement): AutofillFieldKind | null {
  if (!isFillableInput(input)) return null;
  const scores = scoreInput(input);
  const candidates: Array<[AutofillFieldKind, number]> = [
    ["password", scores.password],
    ["otp", scores.otp],
    ["username", scores.username],
  ];
  candidates.sort((left, right) => right[1] - left[1]);
  const best = candidates[0];
  return best !== undefined && best[1] > 0 ? best[0] : null;
}

/** Finds the best username/password field and any unified or split OTP fields. */
export function discoverAutofillFields(
  root: ParentNode,
  preferred?: HTMLInputElement | null,
): DiscoveredAutofillFields {
  const inputs = [...root.querySelectorAll<HTMLInputElement>(INPUT_SELECTOR)].filter(isFillableInput);
  if (preferred !== null && preferred !== undefined && isFillableInput(preferred) && !inputs.includes(preferred)) {
    inputs.unshift(preferred);
  }
  const username = bestInput(inputs, "username", preferred);
  const password = bestInput(inputs, "password", preferred);
  const otp = findOtpInputs(inputs, preferred);
  return { username, password, otp };
}

function bestInput(
  inputs: HTMLInputElement[],
  kind: AutofillFieldKind,
  preferred?: HTMLInputElement | null,
): HTMLInputElement | null {
  const ranked = inputs
    .map((input, index) => ({ input, index, score: scoreInput(input)[kind] }))
    .filter((candidate) => candidate.score > 0)
    .sort((left, right) => {
      const preferredScore = Number(right.input === preferred) - Number(left.input === preferred);
      return right.score - left.score || preferredScore || left.index - right.index;
    });
  return ranked[0]?.input ?? null;
}

function findOtpInputs(inputs: HTMLInputElement[], preferred?: HTMLInputElement | null): HTMLInputElement[] {
  // Check for a segmented verification-code control before ranking individual
  // inputs. Numeric one-character fields otherwise look like a single weak OTP
  // candidate and the first box would win the ranking.
  const split = inputs.filter(isSingleDigitInput);
  const splitHasHint = split.some((input) => scoreInput(input).otp >= 80);
  if (split.length >= 6 && split.length <= 8 && splitHasHint) {
    return split;
  }

  const ranked = inputs
    .map((input, index) => ({ input, index, score: scoreInput(input).otp }))
    .filter((candidate) => candidate.score > 0)
    .sort((left, right) => {
      const preferredScore = Number(right.input === preferred) - Number(left.input === preferred);
      return right.score - left.score || preferredScore || left.index - right.index;
    });
  const unified = ranked[0];
  if (unified !== undefined && unified.score >= 55) return [unified.input];

  // Many MFA forms render six or seven one-character inputs without an
  // autocomplete attribute. If no strong group hint is present, avoid filling
  // an arbitrary numeric field.
  return unified === undefined ? [] : [unified.input];
}

function isSingleDigitInput(input: HTMLInputElement): boolean {
  const maxLength = input.maxLength > 0 ? input.maxLength : Number(input.getAttribute("maxlength") ?? 0);
  const inputMode = (input.inputMode || input.getAttribute("inputmode") || "").toLowerCase();
  const pattern = input.getAttribute("pattern") ?? "";
  return maxLength === 1
    && (input.type === "tel" || input.type === "number" || inputMode === "numeric" || inputMode === "decimal" || NUMERIC_PATTERN.test(pattern));
}

function scoreInput(input: HTMLInputElement): Record<AutofillFieldKind, number> {
  const autocomplete = (input.autocomplete || input.getAttribute("autocomplete") || "").toLowerCase();
  const type = input.type.toLowerCase();
  const context = fieldContext(input);
  const password = type === "password" ? 100 : autocomplete.includes("password") ? 95 : PASSWORD_HINTS.test(context) ? 70 : 0;
  const otp = autocomplete.includes("one-time-code")
    ? 100
    : OTP_HINTS.test(context)
      ? 80
      : looksLikeNumericCode(input)
        ? 55
        : 0;
  const username = autocomplete.includes("username")
    ? 100
    : autocomplete.includes("email") || type === "email"
      ? 95
      : USERNAME_HINTS.test(context)
        ? 70
        : 0;
  return { username, password, otp };
}

function looksLikeNumericCode(input: HTMLInputElement): boolean {
  const pattern = input.getAttribute("pattern") ?? "";
  const maxLength = input.maxLength > 0 ? input.maxLength : Number(input.getAttribute("maxlength") ?? 0);
  const inputMode = (input.inputMode || input.getAttribute("inputmode") || "").toLowerCase();
  return (maxLength === 6 || maxLength === 7 || maxLength === 8)
    && (input.type === "tel" || input.type === "number" || inputMode === "numeric" || NUMERIC_PATTERN.test(pattern));
}

function fieldContext(input: HTMLInputElement): string {
  const values: string[] = [];
  const add = (value: string | null | undefined) => {
    const normalized = value?.trim();
    if (normalized !== undefined && normalized !== "") values.push(normalized);
  };
  add(input.getAttribute("autocomplete"));
  add(input.getAttribute("aria-label"));
  add(input.getAttribute("placeholder"));
  add(input.getAttribute("title"));
  add(input.getAttribute("name"));
  add(input.id);
  add(input.className);
  for (const label of input.labels ?? []) add(label.textContent);
  const root = input.getRootNode();
  if (root instanceof Document || root instanceof ShadowRoot || root instanceof Element) {
    const labelledBy = input.getAttribute("aria-labelledby")?.split(/\s+/u) ?? [];
    for (const id of labelledBy) {
      const label = [...root.querySelectorAll<HTMLElement>("[id]")].find((candidate) => candidate.id === id);
      add(label?.textContent);
    }
    if (input.id !== "") {
      const label = [...root.querySelectorAll<HTMLLabelElement>("label[for]")]
        .find((candidate) => candidate.htmlFor === input.id);
      add(label?.textContent);
    }
  }
  add(input.closest("label")?.textContent);
  const previous = input.previousElementSibling;
  if (previous?.tagName === "LABEL") add(previous.textContent);
  else if (previous !== null) add(previous.textContent?.slice(0, 120));
  let ancestor = input.parentElement;
  for (let depth = 0; depth < 2 && ancestor !== null; depth += 1, ancestor = ancestor.parentElement) {
    add(ancestor.getAttribute("aria-label"));
    add(ancestor.getAttribute("name"));
    add(ancestor.getAttribute("id"));
    add(ancestor.className);
    if (ancestor.tagName === "FIELDSET" || ancestor.getAttribute("role") === "group") add(ancestor.textContent?.slice(0, 200));
  }
  return values.join(" ").toLowerCase();
}

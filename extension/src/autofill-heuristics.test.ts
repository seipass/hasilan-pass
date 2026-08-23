// @vitest-environment jsdom

import { afterEach, describe, expect, it } from "vitest";

import {
  classifyAutofillInput,
  discoverAutofillFields,
} from "./autofill-heuristics";

afterEach(() => {
  document.body.replaceChildren();
});

function visible<T extends HTMLInputElement>(input: T): T {
  Object.defineProperty(input, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ width: 180, height: 32, top: 0, left: 0, right: 180, bottom: 32 }),
  });
  return input;
}

describe("autofill field heuristics", () => {
  it("recognizes username fields from labels and names", () => {
    const form = document.createElement("form");
    const label = document.createElement("label");
    label.textContent = "Account email";
    const input = visible(document.createElement("input"));
    input.name = "identifier";
    label.append(input);
    form.append(label);
    document.body.append(form);

    expect(classifyAutofillInput(input)).toBe("username");
    expect(discoverAutofillFields(form).username).toBe(input);
  });

  it("does not treat a generic search field as a username", () => {
    const input = visible(document.createElement("input"));
    input.type = "search";
    input.placeholder = "Search this site";
    document.body.append(input);

    expect(classifyAutofillInput(input)).toBeNull();
  });

  it("finds a split six-digit verification code", () => {
    const fieldset = document.createElement("fieldset");
    const legend = document.createElement("legend");
    legend.textContent = "Enter your verification code";
    fieldset.append(legend);
    const inputs = Array.from({ length: 6 }, () => {
      const input = visible(document.createElement("input"));
      input.type = "tel";
      input.maxLength = 1;
      input.inputMode = "numeric";
      return input;
    });
    fieldset.append(...inputs);
    document.body.append(fieldset);

    const fields = discoverAutofillFields(fieldset, inputs[0]);
    expect(fields.otp).toEqual(inputs);
    expect(fields.username).toBeNull();
    expect(fields.password).toBeNull();
  });

  it("prefers an explicitly marked password over nearby text fields", () => {
    const form = document.createElement("form");
    const text = visible(document.createElement("input"));
    text.name = "login";
    const password = visible(document.createElement("input"));
    password.type = "password";
    password.autocomplete = "current-password";
    form.append(text, password);
    document.body.append(form);

    const fields = discoverAutofillFields(form, password);
    expect(fields.username).toBe(text);
    expect(fields.password).toBe(password);
  });
});

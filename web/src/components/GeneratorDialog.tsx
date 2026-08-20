import { useState, type FormEvent } from "react";

import { copySecret, messageFromError } from "../security";
import type { SharedVaultRuntime } from "../runtime";
import { Dialog } from "./Dialog";

interface GeneratorDialogProps {
  runtime: SharedVaultRuntime;
  onClose: () => void;
  onUse: (password: string) => void;
  onNotice: (message: string) => void;
}

export function GeneratorDialog({ runtime, onClose, onUse, onNotice }: GeneratorDialogProps) {
  const [mode, setMode] = useState<"password" | "passphrase">("password");
  const [generated, setGenerated] = useState("");
  const [error, setError] = useState<string | null>(null);

  function generate(event?: FormEvent<HTMLFormElement>): void {
    event?.preventDefault();
    const form = event?.currentTarget;
    try {
      const value = mode === "password"
        ? runtime.generatePassword(JSON.stringify({
            length: numberFrom(form, "length", 24),
            uppercase: checked(form, "uppercase", true),
            lowercase: checked(form, "lowercase", true),
            numbers: checked(form, "numbers", true),
            symbols: checked(form, "symbols", true),
            minimumNumbers: 1,
            minimumSymbols: 1,
            excludeAmbiguous: checked(form, "ambiguous", true),
          }))
        : runtime.generatePassphrase(JSON.stringify({
            wordCount: numberFrom(form, "words", 6),
            separator: textFrom(form, "separator", "-"),
            capitalize: checked(form, "capitalize", false),
            includeNumber: checked(form, "includeNumber", false),
          }));
      setGenerated(value);
      setError(null);
    } catch (caught) {
      setError(messageFromError(caught));
    }
  }

  async function copy(): Promise<void> {
    if (generated === "") return;
    try {
      await copySecret(generated);
      onNotice("Generated secret copied. Clipboard clearing is scheduled in 30 seconds.");
    } catch (caught) {
      setError(messageFromError(caught));
    }
  }

  return (
    <Dialog description="Randomness comes from the browser CSPRNG through the shared Rust core." onClose={onClose} title="Secure generator">
      <div className="segmented-control">
        <button className={mode === "password" ? "active" : ""} onClick={() => setMode("password")} type="button">Password</button>
        <button className={mode === "passphrase" ? "active" : ""} onClick={() => setMode("passphrase")} type="button">Passphrase</button>
      </div>
      <form className="generator-form" onSubmit={generate}>
        {mode === "password" ? (
          <>
            <label>Length<input defaultValue="24" max="256" min="8" name="length" type="number" /></label>
            <div className="option-grid">
              <Toggle defaultChecked label="Uppercase" name="uppercase" />
              <Toggle defaultChecked label="Lowercase" name="lowercase" />
              <Toggle defaultChecked label="Numbers" name="numbers" />
              <Toggle defaultChecked label="Symbols" name="symbols" />
              <Toggle defaultChecked label="Avoid ambiguous" name="ambiguous" />
            </div>
          </>
        ) : (
          <>
            <label>Words<input defaultValue="6" max="20" min="3" name="words" type="number" /></label>
            <label>Separator<input defaultValue="-" maxLength={8} name="separator" /></label>
            <div className="option-grid">
              <Toggle label="Capitalize" name="capitalize" />
              <Toggle label="Include number" name="includeNumber" />
            </div>
          </>
        )}
        <button className="primary-button" type="submit">Generate</button>
      </form>
      {error === null ? null : <p className="form-error" role="alert">{error}</p>}
      {generated === "" ? null : (
        <div className="generated-result">
          <code>{generated}</code>
          <div>
            <button className="quiet-button" onClick={() => void copy()} type="button">Copy</button>
            <button className="primary-button" onClick={() => onUse(generated)} type="button">Use for login</button>
          </div>
        </div>
      )}
    </Dialog>
  );
}

function Toggle({ name, label, defaultChecked = false }: { name: string; label: string; defaultChecked?: boolean }) {
  return <label className="checkbox-row"><input defaultChecked={defaultChecked} name={name} type="checkbox" />{label}</label>;
}

function numberFrom(form: HTMLFormElement | undefined, name: string, fallback: number): number {
  const control = form?.elements.namedItem(name);
  return control instanceof HTMLInputElement ? control.valueAsNumber : fallback;
}

function textFrom(form: HTMLFormElement | undefined, name: string, fallback: string): string {
  const control = form?.elements.namedItem(name);
  return control instanceof HTMLInputElement ? control.value : fallback;
}

function checked(form: HTMLFormElement | undefined, name: string, fallback: boolean): boolean {
  const control = form?.elements.namedItem(name);
  return control instanceof HTMLInputElement ? control.checked : fallback;
}

import { useState, type FormEvent } from "react";

import type {
  EditableItemDraft,
  FolderSummary,
  GenericEditableItemKind,
  VaultItem,
} from "../types";
import { Dialog } from "./Dialog";
import type { LoginDestination } from "./LoginEditor";

interface ItemEditorProps {
  kind: GenericEditableItemKind;
  item: VaultItem | null;
  busy: boolean;
  onClose: () => void;
  destinations: LoginDestination[];
  folders: FolderSummary[];
  onSave: (
    draft: EditableItemDraft,
    item: VaultItem | null,
    destination: LoginDestination,
    folderId: string | null,
  ) => Promise<void>;
}

export function ItemEditor({
  kind,
  item,
  busy,
  destinations,
  folders,
  onClose,
  onSave,
}: ItemEditorProps) {
  const [showPrivate, setShowPrivate] = useState(false);
  const values = item?.data.kind === kind ? item.data.value : {};
  const currentDestination = destinationForItem(item, destinations);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const destinationId = requiredText(form, "destination");
    const destination = destinations.find((candidate) => candidate.id === destinationId);
    if (destination === undefined) throw new Error("The selected vault destination is unavailable.");
    await onSave(
      buildDraft(kind, form),
      item,
      destination,
      optionalText(form, "folder"),
    );
  }

  const label = itemKindLabel(kind);
  return (
    <Dialog
      description="The complete item is validated and encrypted in Rust before it leaves this device."
      onClose={onClose}
      title={item === null ? `New ${label.toLowerCase()}` : `Edit ${label.toLowerCase()}`}
      wide
    >
      <form className="editor-form" onSubmit={(event) => void submit(event)}>
        <div className="field-grid two-columns">
          <label className="span-two">
            Vault destination
            <select
              defaultValue={currentDestination?.id ?? "personal"}
              disabled={item !== null}
              name={item === null ? "destination" : undefined}
              required
            >
              {destinations.map((destination) => (
                <option
                  disabled={item === null && !destination.writable}
                  key={destination.id}
                  value={destination.id}
                >{destination.label}{destination.writable ? "" : " (read-only)"}</option>
              ))}
            </select>
            {item === null ? null : (
              <input name="destination" type="hidden" value={currentDestination?.id ?? "personal"} />
            )}
            {item === null ? null : <small>Ownership is immutable after the first encrypted upload.</small>}
          </label>
          <label className="span-two">
            Personal folder
            <select defaultValue={item?.folderId ?? ""} name="folder">
              <option value="">No folder</option>
              {folders.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}
            </select>
            <small>Organization items use collections; a folder selection is ignored for them.</small>
          </label>
          <label className="span-two">
            Name
            <input defaultValue={item?.name ?? ""} maxLength={2000} name="name" required />
          </label>

          <StructuredFields kind={kind} showPrivate={showPrivate} values={values} />

          <label className="span-two">
            {kind === "secureNote" ? "Secure note" : "Notes"}
            <textarea defaultValue={item?.notes ?? ""} maxLength={65536} name="notes" rows={kind === "secureNote" ? 12 : 5} />
          </label>
        </div>
        {kind === "card" || kind === "identity" || kind === "sshKey" ? (
          <label className="checkbox-row">
            <input checked={showPrivate} onChange={() => setShowPrivate((shown) => !shown)} type="checkbox" />
            Show private fields
          </label>
        ) : null}
        <label className="checkbox-row">
          <input defaultChecked={item?.favorite ?? false} name="favorite" type="checkbox" />
          Add to favorites
        </label>
        <footer className="dialog-actions">
          <button className="quiet-button" onClick={onClose} type="button">Cancel</button>
          <button className="primary-button" disabled={busy} type="submit">
            {busy ? "Encrypting…" : "Encrypt and save"}
          </button>
        </footer>
      </form>
    </Dialog>
  );
}

function StructuredFields({
  kind,
  showPrivate,
  values,
}: {
  kind: GenericEditableItemKind;
  showPrivate: boolean;
  values: Record<string, unknown>;
}) {
  if (kind === "secureNote") return null;
  if (kind === "card") {
    return (
      <>
        <label>
          Cardholder name
          <input autoComplete="cc-name" defaultValue={stringValue(values, "cardholderName")} name="cardholderName" />
        </label>
        <label>
          Brand
          <input autoComplete="off" defaultValue={stringValue(values, "brand")} name="brand" />
        </label>
        <label className="span-two">
          Card number
          <input autoComplete="cc-number" defaultValue={stringValue(values, "number")} inputMode="numeric" name="number" type={showPrivate ? "text" : "password"} />
        </label>
        <label>
          Expiration month
          <input autoComplete="cc-exp-month" defaultValue={stringValue(values, "expMonth")} inputMode="numeric" maxLength={2} name="expMonth" />
        </label>
        <label>
          Expiration year
          <input autoComplete="cc-exp-year" defaultValue={stringValue(values, "expYear")} inputMode="numeric" maxLength={4} name="expYear" />
        </label>
        <label>
          Security code
          <input autoComplete="cc-csc" defaultValue={stringValue(values, "code")} inputMode="numeric" name="code" type={showPrivate ? "text" : "password"} />
        </label>
      </>
    );
  }
  if (kind === "identity") {
    return (
      <>
        <label>
          Title
          <input autoComplete="honorific-prefix" defaultValue={stringValue(values, "title")} name="title" />
        </label>
        <label>
          First name
          <input autoComplete="given-name" defaultValue={stringValue(values, "firstName")} name="firstName" />
        </label>
        <label>
          Middle name
          <input autoComplete="additional-name" defaultValue={stringValue(values, "middleName")} name="middleName" />
        </label>
        <label>
          Last name
          <input autoComplete="family-name" defaultValue={stringValue(values, "lastName")} name="lastName" />
        </label>
        <label>
          Company
          <input autoComplete="organization" defaultValue={stringValue(values, "company")} name="company" />
        </label>
        <label>
          Username
          <input autoComplete="username" defaultValue={stringValue(values, "username")} name="username" />
        </label>
        <label>
          Email
          <input autoComplete="email" defaultValue={stringValue(values, "email")} name="email" type="email" />
        </label>
        <label>
          Phone
          <input autoComplete="tel" defaultValue={stringValue(values, "phone")} name="phone" type="tel" />
        </label>
        <label className="span-two">
          Address line 1
          <input autoComplete="address-line1" defaultValue={stringValue(values, "address1")} name="address1" />
        </label>
        <label className="span-two">
          Address line 2
          <input autoComplete="address-line2" defaultValue={stringValue(values, "address2")} name="address2" />
        </label>
        <label className="span-two">
          Address line 3
          <input autoComplete="address-line3" defaultValue={stringValue(values, "address3")} name="address3" />
        </label>
        <label>
          City
          <input autoComplete="address-level2" defaultValue={stringValue(values, "city")} name="city" />
        </label>
        <label>
          State / province
          <input autoComplete="address-level1" defaultValue={stringValue(values, "state")} name="state" />
        </label>
        <label>
          Postal code
          <input autoComplete="postal-code" defaultValue={stringValue(values, "postalCode")} name="postalCode" />
        </label>
        <label>
          Country
          <input autoComplete="country-name" defaultValue={stringValue(values, "country")} name="country" />
        </label>
        <label>
          Social security number
          <input autoComplete="off" defaultValue={stringValue(values, "ssn")} name="ssn" type={showPrivate ? "text" : "password"} />
        </label>
        <label>
          Passport number
          <input autoComplete="off" defaultValue={stringValue(values, "passportNumber")} name="passportNumber" type={showPrivate ? "text" : "password"} />
        </label>
        <label>
          License number
          <input autoComplete="off" defaultValue={stringValue(values, "licenseNumber")} name="licenseNumber" type={showPrivate ? "text" : "password"} />
        </label>
      </>
    );
  }
  return (
    <>
      <label className="span-two">
        Private key
        <textarea
          autoComplete="off"
          className={showPrivate ? undefined : "masked-textarea"}
          defaultValue={stringValue(values, "privateKey")}
          maxLength={262144}
          name="privateKey"
          required
          rows={8}
          spellCheck={false}
        />
      </label>
      <label className="span-two">
        Public key
        <textarea autoComplete="off" defaultValue={stringValue(values, "publicKey")} maxLength={65536} name="publicKey" required rows={3} spellCheck={false} />
      </label>
      <label className="span-two">
        Fingerprint
        <input autoComplete="off" defaultValue={stringValue(values, "keyFingerprint")} maxLength={4000} name="keyFingerprint" required spellCheck={false} />
      </label>
    </>
  );
}

function buildDraft(kind: GenericEditableItemKind, form: FormData): EditableItemDraft {
  const common = {
    name: requiredText(form, "name"),
    notes: optionalVerbatimText(form, "notes"),
    favorite: form.get("favorite") === "on",
  };
  if (kind === "secureNote") {
    return { ...common, data: { kind, value: {} } };
  }
  if (kind === "card") {
    return {
      ...common,
      data: {
        kind,
        value: {
          cardholderName: optionalText(form, "cardholderName"),
          expMonth: optionalText(form, "expMonth"),
          expYear: optionalText(form, "expYear"),
          code: optionalVerbatimText(form, "code"),
          brand: optionalText(form, "brand"),
          number: optionalVerbatimText(form, "number"),
        },
      },
    };
  }
  if (kind === "identity") {
    return {
      ...common,
      data: {
        kind,
        value: {
          title: optionalText(form, "title"),
          firstName: optionalText(form, "firstName"),
          middleName: optionalText(form, "middleName"),
          lastName: optionalText(form, "lastName"),
          address1: optionalText(form, "address1"),
          address2: optionalText(form, "address2"),
          address3: optionalText(form, "address3"),
          city: optionalText(form, "city"),
          state: optionalText(form, "state"),
          postalCode: optionalText(form, "postalCode"),
          country: optionalText(form, "country"),
          company: optionalText(form, "company"),
          email: optionalText(form, "email"),
          phone: optionalText(form, "phone"),
          ssn: optionalVerbatimText(form, "ssn"),
          username: optionalText(form, "username"),
          passportNumber: optionalVerbatimText(form, "passportNumber"),
          licenseNumber: optionalVerbatimText(form, "licenseNumber"),
        },
      },
    };
  }
  return {
    ...common,
    data: {
      kind,
      value: {
        privateKey: requiredVerbatimText(form, "privateKey"),
        publicKey: requiredVerbatimText(form, "publicKey"),
        keyFingerprint: requiredText(form, "keyFingerprint"),
      },
    },
  };
}

function destinationForItem(
  item: VaultItem | null,
  destinations: LoginDestination[],
): LoginDestination | undefined {
  if (item === null || item.organizationId === null) {
    return destinations.find((destination) => destination.organizationId === null);
  }
  return destinations.find(
    (destination) =>
      destination.organizationId === item.organizationId
      && destination.collectionIds.length === item.collectionIds.length
      && destination.collectionIds.every((id) => item.collectionIds.includes(id)),
  );
}

function stringValue(values: Record<string, unknown>, key: string): string {
  const value = values[key];
  return typeof value === "string" ? value : "";
}

function requiredText(data: FormData, name: string): string {
  const value = optionalText(data, name);
  if (value === null) throw new Error(`${name} is required.`);
  return value;
}

function requiredVerbatimText(data: FormData, name: string): string {
  const value = optionalVerbatimText(data, name);
  if (value === null) throw new Error(`${name} is required.`);
  return value;
}

function optionalText(data: FormData, name: string): string | null {
  const value = data.get(name);
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

function optionalVerbatimText(data: FormData, name: string): string | null {
  const value = data.get(name);
  if (typeof value !== "string" || value.trim() === "") return null;
  return value;
}

function itemKindLabel(kind: GenericEditableItemKind): string {
  return ({
    secureNote: "Secure note",
    card: "Payment card",
    identity: "Identity",
    sshKey: "SSH key",
  } as const)[kind];
}

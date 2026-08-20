import { useEffect, useMemo, useState, type FormEvent } from "react";

import type { ApiClient } from "../api";
import type { SharedVaultRuntime } from "../runtime";
import { messageFromError } from "../security";
import type {
  CollectionResponse,
  OrganizationMemberResponse,
  OrganizationResponse,
  OrganizationRole,
} from "../types";
import { Dialog } from "./Dialog";

interface OrganizationsDialogProps {
  api: ApiClient;
  runtime: SharedVaultRuntime;
  organizations: OrganizationResponse[];
  initialInvitationToken: string | null;
  onClose: () => void;
  onInvitationAccepted: () => void;
  onNotice: (message: string) => void;
  onReload: () => Promise<void>;
}

const INVITABLE_ROLES: OrganizationRole[] = ["admin", "manager", "user"];

export function OrganizationsDialog({
  api,
  runtime,
  organizations,
  initialInvitationToken,
  onClose,
  onInvitationAccepted,
  onNotice,
  onReload,
}: OrganizationsDialogProps) {
  const [selectedId, setSelectedId] = useState<string | null>(organizations[0]?.id ?? null);
  const [members, setMembers] = useState<OrganizationMemberResponse[]>([]);
  const [collections, setCollections] = useState<CollectionResponse[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deliveryToken, setDeliveryToken] = useState<string | null>(null);
  const selected = useMemo(
    () => organizations.find((organization) => organization.id === selectedId) ?? null,
    [organizations, selectedId],
  );

  useEffect(() => {
    if (selectedId === null) setSelectedId(organizations[0]?.id ?? null);
  }, [organizations, selectedId]);

  useEffect(() => {
    if (selected?.status !== "confirmed") {
      setMembers([]);
      setCollections([]);
      return;
    }
    let active = true;
    void Promise.all([
      api.listOrganizationMembers(selected.id),
      api.listCollections(selected.id),
    ])
      .then(([nextMembers, nextCollections]) => {
        if (active) {
          setMembers(nextMembers);
          setCollections(nextCollections);
        }
      })
      .catch((caught: unknown) => {
        if (active) setError(messageFromError(caught));
      });
    return () => {
      active = false;
    };
  }, [api, selected]);

  async function run(action: () => Promise<void>): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (caught) {
      setError(messageFromError(caught));
    } finally {
      setBusy(false);
    }
  }

  async function createOrganization(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = required(data, "name");
    await run(async () => {
      const ownKey = await api.sharingKey();
      const id = crypto.randomUUID();
      const encryptedOrganizationKey = runtime.createOrganizationKey(id, ownKey.publicKey);
      await api.createOrganization({ id, name, encryptedOrganizationKey });
      await onReload();
      setSelectedId(id);
      form.reset();
      onNotice("Organization key created locally and only its encrypted wrapper was uploaded.");
    });
  }

  async function acceptInvitation(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const token = required(new FormData(form), "token");
    await run(async () => {
      const membership = await api.acceptOrganizationInvitation(token);
      const organization = organizations.find((candidate) => candidate.memberId === membership.id);
      await onReload();
      if (organization !== undefined && membership.encryptedOrganizationKey !== null) {
        runtime.openOrganizationKey(organization.id, membership.encryptedOrganizationKey);
      }
      form.reset();
      onInvitationAccepted();
      onNotice("Invitation accepted. An owner or admin must confirm the membership.");
    });
  }

  async function invite(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (selected === null) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const email = required(data, "email").toLowerCase();
    const role = required(data, "role") as OrganizationRole;
    await run(async () => {
      const recipient = await api.lookupSharingKey(email);
      const encryptedOrganizationKey = runtime.sealOrganizationKey(
        selected.id,
        recipient.publicKey,
      );
      const invitation = await api.inviteOrganizationMember(selected.id, {
        email,
        role,
        encryptedOrganizationKey,
      });
      setDeliveryToken(invitation.invitationToken);
      setMembers(await api.listOrganizationMembers(selected.id));
      form.reset();
      onNotice(invitation.delivery === "smtp"
        ? "Invitation submitted to the configured SMTP relay."
        : "Invitation created. Deliver the one-time token through a trusted channel.");
    });
  }

  async function confirmMember(memberId: string): Promise<void> {
    if (selected === null) return;
    await run(async () => {
      await api.confirmOrganizationMember(selected.id, memberId);
      setMembers(await api.listOrganizationMembers(selected.id));
      onNotice("Membership confirmed; authorized encrypted items were added to their sync feed.");
    });
  }

  async function changeRole(memberId: string, role: OrganizationRole): Promise<void> {
    if (selected === null) return;
    await run(async () => {
      await api.changeOrganizationMemberRole(selected.id, memberId, role);
      setMembers(await api.listOrganizationMembers(selected.id));
      onNotice("Member role updated.");
    });
  }

  async function removeMember(member: OrganizationMemberResponse): Promise<void> {
    if (selected === null || !window.confirm(`Remove ${member.email} from this organization?`)) {
      return;
    }
    await run(async () => {
      await api.removeOrganizationMember(selected.id, member.id);
      setMembers(await api.listOrganizationMembers(selected.id));
      onNotice("Member removed and organization ciphertext purged from their active sync view.");
    });
  }

  async function createCollection(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (selected === null) return;
    const form = event.currentTarget;
    const name = required(new FormData(form), "name");
    await run(async () => {
      await api.createCollection(selected.id, name);
      setCollections(await api.listCollections(selected.id));
      form.reset();
      await onReload();
      onNotice("Collection created.");
    });
  }

  async function grantAccess(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (selected === null) return;
    const data = new FormData(event.currentTarget);
    const collectionId = required(data, "collectionId");
    const memberId = required(data, "memberId");
    const manage = data.get("manage") === "on";
    await run(async () => {
      await api.putCollectionAccess(selected.id, collectionId, {
        memberId,
        readOnly: manage ? false : data.get("readOnly") === "on",
        hidePasswords: manage ? false : data.get("hidePasswords") === "on",
        manage,
      });
      onNotice("Collection access updated and the member's encrypted sync feed reconciled.");
    });
  }

  const canAdmin = selected !== null && ["owner", "admin"].includes(selected.role);

  return (
    <Dialog
      description="Organization keys are generated and opened in the shared Rust/WASM trust boundary. The server stores only recipient-bound wrappers and encrypted vault objects."
      onClose={onClose}
      title="Organizations & collections"
      wide
    >
      {error === null ? null : <p className="form-error" role="alert">{error}</p>}
      <div className="organization-layout">
        <aside className="organization-list" aria-label="Organizations">
          {organizations.map((organization) => (
            <button
              className={selectedId === organization.id ? "active" : ""}
              key={organization.id}
              onClick={() => setSelectedId(organization.id)}
              type="button"
            >
              <strong>{organization.name}</strong>
              <span>{organization.role} · {organization.status}</span>
            </button>
          ))}
          <form className="compact-form" onSubmit={(event) => void createOrganization(event)}>
            <label>
              New organization
              <input maxLength={128} name="name" placeholder="Organization name" required />
            </label>
            <button className="primary-button" disabled={busy} type="submit">Create</button>
          </form>
          <form className="compact-form" onSubmit={(event) => void acceptInvitation(event)}>
            <label>
              Invitation token
              <input autoComplete="off" defaultValue={initialInvitationToken ?? ""} name="token" required spellCheck={false} />
            </label>
            <button className="quiet-button" disabled={busy} type="submit">Accept</button>
          </form>
        </aside>

        <section className="organization-detail">
          {selected === null ? (
            <div className="empty-vault"><h3>No organization selected</h3></div>
          ) : (
            <>
              <header>
                <p className="eyebrow">{selected.role} · {selected.status}</p>
                <h3>{selected.name}</h3>
                <p>{runtime.hasOrganizationKey(selected.id) ? "Organization key open in this tab" : "Organization key unavailable"}</p>
              </header>

              {deliveryToken === null ? null : (
                <div className="delivery-token">
                  <strong>One-time delivery token</strong>
                  <code>{deliveryToken}</code>
                  <button
                    className="quiet-button"
                    onClick={() => void navigator.clipboard.writeText(deliveryToken)}
                    type="button"
                  >Copy token</button>
                </div>
              )}

              {selected.status !== "confirmed" ? (
                <p className="dialog-description">Access begins only after an administrator confirms an accepted membership.</p>
              ) : (
                <>
                  <section className="organization-section">
                    <h4>Collections</h4>
                    <div className="collection-chips">
                      {collections.map((collection) => (
                        <span key={collection.id}>
                          {collection.name}
                          {collection.readOnly ? " · read-only" : ""}
                          {collection.hidePasswords ? " · hide passwords" : ""}
                        </span>
                      ))}
                    </div>
                    {canAdmin || selected.role === "manager" ? (
                      <form className="inline-form" onSubmit={(event) => void createCollection(event)}>
                        <input maxLength={128} name="name" placeholder="Collection name" required />
                        <button className="quiet-button" disabled={busy} type="submit">Add collection</button>
                      </form>
                    ) : null}
                  </section>

                  <section className="organization-section">
                    <h4>Members</h4>
                    <div className="member-table">
                      {members.map((member) => (
                        <div className="member-row" key={member.id}>
                          <div><strong>{member.email}</strong><span>{member.status}</span></div>
                          {canAdmin && member.status === "confirmed" ? (
                            <select
                              aria-label={`Role for ${member.email}`}
                              disabled={busy}
                              onChange={(event) => void changeRole(member.id, event.target.value as OrganizationRole)}
                              value={member.role}
                            >
                              <option value="owner">Owner</option>
                              <option value="admin">Admin</option>
                              <option value="manager">Manager</option>
                              <option value="user">User</option>
                            </select>
                          ) : <span>{member.role}</span>}
                          {canAdmin && member.status === "accepted" ? (
                            <button className="quiet-button" disabled={busy} onClick={() => void confirmMember(member.id)} type="button">Confirm</button>
                          ) : null}
                          {canAdmin && member.id !== selected.memberId ? (
                            <button className="danger-button" disabled={busy} onClick={() => void removeMember(member)} type="button">Remove</button>
                          ) : null}
                        </div>
                      ))}
                    </div>
                  </section>

                  {canAdmin ? (
                    <section className="organization-section split-section">
                      <form className="compact-form" onSubmit={(event) => void invite(event)}>
                        <h4>Invite existing account</h4>
                        <input name="email" placeholder="person@example.com" required type="email" />
                        <select defaultValue="user" name="role">
                          {INVITABLE_ROLES.map((role) => <option key={role} value={role}>{role}</option>)}
                        </select>
                        <button className="primary-button" disabled={busy || !runtime.hasOrganizationKey(selected.id)} type="submit">Create invitation</button>
                      </form>
                      <form className="compact-form" onSubmit={(event) => void grantAccess(event)}>
                        <h4>Collection access</h4>
                        <select name="collectionId" required>
                          <option value="">Choose collection</option>
                          {collections.map((collection) => <option key={collection.id} value={collection.id}>{collection.name}</option>)}
                        </select>
                        <select name="memberId" required>
                          <option value="">Choose confirmed member</option>
                          {members.filter((member) => member.status === "confirmed").map((member) => <option key={member.id} value={member.id}>{member.email}</option>)}
                        </select>
                        <label className="checkbox-row"><input name="readOnly" type="checkbox" />Read only</label>
                        <label className="checkbox-row"><input name="hidePasswords" type="checkbox" />Hide passwords in official clients</label>
                        <label className="checkbox-row"><input name="manage" type="checkbox" />Manage collection</label>
                        <button className="quiet-button" disabled={busy} type="submit">Apply access</button>
                      </form>
                    </section>
                  ) : null}
                </>
              )}
            </>
          )}
        </section>
      </div>
      <footer className="dialog-actions">
        <button className="quiet-button" onClick={onClose} type="button">Close</button>
      </footer>
    </Dialog>
  );
}

function required(data: FormData, name: string): string {
  const value = data.get(name);
  if (typeof value !== "string" || value.trim() === "") throw new Error(`${name} is required.`);
  return value.trim();
}

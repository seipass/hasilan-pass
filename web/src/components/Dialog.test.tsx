import { fireEvent, render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { Dialog } from "./Dialog";

describe("Dialog", () => {
  it("announces itself, traps keyboard focus, closes with Escape, and restores focus", () => {
    const trigger = document.createElement("button");
    trigger.textContent = "Open settings";
    document.body.append(trigger);
    trigger.focus();
    const onClose = vi.fn();
    const view = render(
      <Dialog description="A private settings dialog." onClose={onClose} title="Settings">
        <button type="button">First action</button>
        <input aria-label="Setting value" />
        <button type="button">Last action</button>
      </Dialog>,
    );

    const dialog = view.getByRole("dialog", {
      description: "A private settings dialog.",
      name: "Settings",
    });
    expect(document.activeElement).toBe(dialog);

    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(view.getByRole("button", { name: "Close dialog" }));

    view.getByRole("button", { name: "Last action" }).focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(view.getByRole("button", { name: "Close dialog" }));

    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(view.getByRole("button", { name: "Last action" }));

    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(onClose).toHaveBeenCalledOnce();
    view.unmount();
    expect(document.activeElement).toBe(trigger);
    trigger.remove();
  });

  it("keeps focus on an empty dialog", () => {
    const view = render(
      <Dialog onClose={vi.fn()} title="Information">
        <p>No actions are available.</p>
      </Dialog>,
    );
    const dialog = view.getByRole("dialog");

    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(view.getByRole("button", { name: "Close dialog" }));
    view.getByRole("button", { name: "Close dialog" }).setAttribute("disabled", "");
    dialog.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(document.activeElement).toBe(dialog);
  });
});

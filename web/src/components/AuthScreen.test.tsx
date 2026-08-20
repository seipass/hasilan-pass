import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { AuthScreen } from "./AuthScreen";

describe("AuthScreen", () => {
  it("renders server errors as inert text", () => {
    const payload = '<img src=x onerror="globalThis.compromised=true">';
    const view = render(
      <AuthScreen
        busy={false}
        error={payload}
        onLogin={vi.fn()}
        onPasskeyLogin={vi.fn()}
        onRegister={vi.fn()}
        onWebauthnMfaLogin={vi.fn()}
      />,
    );

    expect(view.container.querySelector('img[src="x"]')).toBeNull();
    expect(view.container.querySelector("img[onerror]")).toBeNull();
    expect(view.getByRole("alert").textContent).toContain(payload);
  });
});

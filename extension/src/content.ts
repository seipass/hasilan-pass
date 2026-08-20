(() => {
  interface RuntimeLike {
    sendMessage(message: unknown): Promise<unknown>;
    getURL(path: string): string;
    onMessage: {
      addListener(listener: (message: unknown) => void): void;
    };
  }

  interface CredentialSummary {
    id: string;
    name: string;
    username: string | null;
    hasPassword: boolean;
    hasTotp: boolean;
  }

  interface FillCredential {
    id: string;
    username: string | null;
    password: string | null;
    totp: string | null;
  }

  type ContentGlobal = typeof globalThis & {
    __hasilanPassContentV1?: boolean;
    browser?: { runtime: RuntimeLike };
    chrome?: { runtime: RuntimeLike };
  };

  const scope = globalThis as ContentGlobal;
  if (scope.__hasilanPassContentV1 === true) return;
  scope.__hasilanPassContentV1 = true;

  const runtimeCandidate = scope.browser?.runtime ?? scope.chrome?.runtime;
  if (runtimeCandidate === undefined || !isWebPage(location.href)) return;
  const runtime: RuntimeLike = runtimeCandidate;
  const PASSKEY_PAGE_CHANNEL = "hasilan-pass-webauthn-page-v1";

  const inputValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  let focusedInput: HTMLInputElement | null = null;
  let menuHost: HTMLDivElement | null = null;
  let menuRoot: ShadowRoot | null = null;
  let menuCredentials: CredentialSummary[] = [];
  let keyboardSelection = -1;
  const submissionRoots = new WeakSet<Document | ShadowRoot>();

  observeSubmissionRoot(document);

  window.addEventListener("message", (event: MessageEvent<unknown>) => {
    if (!event.isTrusted || event.source !== window || event.origin !== location.origin) return;
    const port = event.ports[0];
    if (port === undefined || !isPasskeyPageRequest(event.data)) return;
    void handlePasskeyPageRequest(event.data, port);
  });

  document.addEventListener("focusin", (event) => {
    const input = inputFromEvent(event);
    if (input !== null && isCredentialInput(input)) {
      const root = input.getRootNode();
      if (root instanceof ShadowRoot) observeSubmissionRoot(root);
      focusedInput = input;
      void showMenu(input, false);
    }
  }, true);

  document.addEventListener("keydown", (event) => {
    const input = inputFromEvent(event);
    if (input === null || input !== focusedInput || menuHost === null) return;
    if (event.key === "ArrowDown" && menuCredentials.length > 0) {
      event.preventDefault();
      keyboardSelection = (keyboardSelection + 1) % menuCredentials.length;
      markKeyboardSelection();
    } else if (event.key === "ArrowUp" && menuCredentials.length > 0) {
      event.preventDefault();
      keyboardSelection = (keyboardSelection - 1 + menuCredentials.length) % menuCredentials.length;
      markKeyboardSelection();
    } else if (event.key === "Enter" && keyboardSelection >= 0) {
      const credential = menuCredentials[keyboardSelection];
      if (credential !== undefined) {
        event.preventDefault();
        void fill(input, credential.id);
      }
    } else if (event.key === "Escape") {
      closeMenu();
    }
  }, true);

  window.addEventListener("scroll", closeMenu, true);
  window.addEventListener("resize", closeMenu, { passive: true });

  runtime.onMessage.addListener((message: unknown) => {
    if (!isOpenMenuMessage(message)) return;
    const active = deepActiveInput();
    const target = active instanceof HTMLInputElement && isCredentialInput(active)
      ? active
      : firstFillable(document.querySelectorAll<HTMLInputElement>('input[type="password"], input[autocomplete~="username"], input[type="email"]'));
    if (target !== null) {
      focusedInput = target;
      void showMenu(target, true);
    }
  });

  async function handlePasskeyPageRequest(
    message: { channel: string; type: "create" | "get"; options: Record<string, unknown> },
    port: MessagePort,
  ): Promise<void> {
    try {
      const encoded = JSON.stringify(message.options);
      if (encoded.length > 128 * 1024) throw new Error("The WebAuthn request exceeded extension limits.");
      const result = await send<Record<string, unknown>>({
        type: message.type === "create" ? "PASSKEY_CREATE" : "PASSKEY_GET",
        pageUrl: withoutFragment(location.href),
        options: message.options,
      });
      port.postMessage(result);
    } catch {
      port.postMessage({
        status: "error",
        name: "UnknownError",
        message: "The vault passkey request could not be completed.",
      });
    } finally {
      port.close();
    }
  }

  async function showMenu(target: HTMLInputElement, force: boolean): Promise<void> {
    if (!force && target.autocomplete.toLowerCase().includes("new-password")) return;
    try {
      const credentials = await send<CredentialSummary[]>({
        type: "CREDENTIALS_FOR_PAGE",
        pageUrl: withoutFragment(location.href),
      });
      if (credentials.length === 0 && !force) {
        closeMenu();
        return;
      }
      renderMenu(target, credentials, null);
    } catch (error) {
      if (force) renderMenu(target, [], errorMessage(error));
    }
  }

  function renderMenu(target: HTMLInputElement, credentials: CredentialSummary[], error: string | null): void {
    closeMenu();
    menuCredentials = credentials;
    keyboardSelection = -1;
    const host = document.createElement("div");
    host.setAttribute("data-hasilan-pass", "menu");
    host.style.position = "fixed";
    host.style.zIndex = "2147483647";
    host.style.margin = "0";
    host.style.padding = "0";
    host.style.border = "0";
    host.style.colorScheme = "dark";
    const rect = target.getBoundingClientRect();
    const width = Math.min(Math.max(rect.width, 280), 390);
    host.style.width = `${width}px`;
    host.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - width - 8))}px`;
    host.style.top = `${Math.min(rect.bottom + 7, window.innerHeight - 280)}px`;
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = MENU_CSS;
    shadow.append(style);
    const panel = element("section", "panel");
    panel.setAttribute("aria-label", "Hasilan Pass credentials");
    const header = element("header", "header");
    const brand = element("strong", "brand", "Hasilan Pass");
    const close = element("button", "close", "×");
    close.type = "button";
    close.setAttribute("aria-label", "Close Hasilan Pass menu");
    close.addEventListener("click", closeMenu);
    header.append(brand, close);
    panel.append(header);

    if (error !== null) {
      const state = element("div", "state");
      state.append(element("strong", "", "Vault locked"), element("p", "", "Open the Hasilan Pass extension to unlock and sync."));
      panel.append(state);
    } else if (credentials.length === 0) {
      const state = element("div", "state");
      state.append(element("strong", "", "No matching login"), element("p", "", "The current URL did not match a saved credential."));
      panel.append(state);
    } else {
      const list = element("div", "list");
      for (const credential of credentials) {
        const button = element("button", "credential");
        button.type = "button";
        const icon = document.createElement("img");
        icon.alt = "";
        icon.className = "glyph";
        icon.src = runtime.getURL("icons/icon.svg");
        const copy = element("span", "copy");
        copy.append(element("strong", "", credential.name), element("small", "", credential.username ?? "No username"));
        const signal = element("span", "signal", credential.hasTotp ? "TOTP" : "Fill");
        button.append(icon, copy, signal);
        button.addEventListener("mousedown", (event) => event.preventDefault());
        button.addEventListener("click", () => void fill(target, credential.id));
        list.append(button);
      }
      panel.append(list);
    }
    shadow.append(panel);
    document.documentElement.append(host);
    menuHost = host;
    menuRoot = shadow;
  }

  async function fill(target: HTMLInputElement, id: string): Promise<void> {
    try {
      let credential: FillCredential | null = await send<FillCredential>({
        type: "FILL_CREDENTIAL",
        id,
        pageUrl: withoutFragment(location.href),
      });
      const treeRoot = target.getRootNode();
      const root: ParentNode = target.form ?? (treeRoot instanceof ShadowRoot ? treeRoot : document);
      const username = firstFillable(root.querySelectorAll<HTMLInputElement>(
        'input[autocomplete~="username"], input[autocomplete~="email"], input[type="email"], input[type="text"]',
      ));
      const password = firstFillable(root.querySelectorAll<HTMLInputElement>(
        'input[autocomplete~="current-password"], input[type="password"]',
      ));
      const oneTimeCode = firstFillable(root.querySelectorAll<HTMLInputElement>('input[autocomplete~="one-time-code"]'));
      if (credential.username !== null && username !== null) setInputValue(username, credential.username);
      if (credential.password !== null && password !== null) setInputValue(password, credential.password);
      if (credential.totp !== null && oneTimeCode !== null) setInputValue(oneTimeCode, credential.totp);
      credential = null;
      closeMenu();
    } catch (error) {
      renderMenu(target, [], errorMessage(error));
    }
  }

  function captureSubmittedCredential(form: HTMLFormElement): void {
    const passwords = [...form.querySelectorAll<HTMLInputElement>('input[type="password"]')]
      .filter(isFillable)
      .filter((input) => input.value !== "");
    if (passwords.length === 0) return;
    const preferred = passwords.find((input) => input.autocomplete.toLowerCase().includes("new-password"))
      ?? passwords.find((input) => input.autocomplete.toLowerCase().includes("current-password"))
      ?? passwords.at(-1);
    if (preferred === undefined || preferred.value.length > 16_384) return;
    const usernameInput = firstFillable(form.querySelectorAll<HTMLInputElement>(
      'input[autocomplete~="username"], input[autocomplete~="email"], input[type="email"], input[type="text"]',
    ));
    const username = usernameInput?.value.trim() || null;
    const message = {
      type: "CAPTURE_CREDENTIAL",
      pageUrl: withoutFragment(location.href),
      username,
      password: preferred.value,
    };
    void send(message).catch(() => undefined);
    message.password = "";
  }

  function observeSubmissionRoot(root: Document | ShadowRoot): void {
    if (submissionRoots.has(root)) return;
    submissionRoots.add(root);
    root.addEventListener("submit", (event: Event) => {
      if (event.target instanceof HTMLFormElement) captureSubmittedCredential(event.target);
    }, true);
  }

  function inputFromEvent(event: Event): HTMLInputElement | null {
    return event.composedPath().find((candidate) => candidate instanceof HTMLInputElement) as HTMLInputElement | undefined ?? null;
  }

  function deepActiveInput(): HTMLInputElement | null {
    let active: Element | null = document.activeElement;
    while (active instanceof HTMLElement) {
      const nested = active.shadowRoot?.activeElement;
      if (nested === null || nested === undefined) break;
      active = nested;
    }
    return active instanceof HTMLInputElement ? active : null;
  }

  function setInputValue(input: HTMLInputElement, value: string): void {
    if (!isFillable(input)) return;
    if (inputValueSetter === undefined) input.value = value;
    else inputValueSetter.call(input, value);
    input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, data: value, inputType: "insertText" }));
    input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }

  function closeMenu(): void {
    menuHost?.remove();
    menuHost = null;
    menuRoot = null;
    menuCredentials = [];
    keyboardSelection = -1;
  }

  function markKeyboardSelection(): void {
    if (menuRoot === null) return;
    const buttons = menuRoot.querySelectorAll<HTMLButtonElement>(".credential");
    buttons.forEach((button, index) => {
      button.classList.toggle("keyboard-selected", index === keyboardSelection);
    });
  }

  function firstFillable(inputs: NodeListOf<HTMLInputElement> | HTMLInputElement[]): HTMLInputElement | null {
    return [...inputs].find(isFillable) ?? null;
  }

  function isCredentialInput(input: HTMLInputElement): boolean {
    const autocomplete = input.autocomplete.toLowerCase();
    return isFillable(input) && (
      input.type === "password"
      || input.type === "email"
      || autocomplete.includes("username")
      || autocomplete.includes("current-password")
      || autocomplete.includes("one-time-code")
    );
  }

  function isFillable(input: HTMLInputElement): boolean {
    if (input.disabled || input.readOnly || input.type === "hidden") return false;
    const rect = input.getBoundingClientRect();
    const style = getComputedStyle(input);
    return rect.width > 0 && rect.height > 0 && style.display !== "none" && style.visibility !== "hidden";
  }

  async function send<T>(body: Record<string, unknown>): Promise<T> {
    const response = await runtime.sendMessage({ channel: "hasilan-pass-extension-v1", ...body });
    if (!isResponse(response)) throw new Error("The extension returned an invalid response.");
    if (!response.ok) throw new Error(response.error);
    return response.data as T;
  }

  function isResponse(value: unknown): value is { ok: boolean; data?: unknown; error?: string } {
    return typeof value === "object" && value !== null && "ok" in value && typeof value.ok === "boolean";
  }

  function isOpenMenuMessage(value: unknown): boolean {
    return typeof value === "object" && value !== null
      && "channel" in value && value.channel === "hasilan-pass-content-v1"
      && "type" in value && value.type === "OPEN_MENU";
  }

  function isPasskeyPageRequest(
    value: unknown,
  ): value is { channel: string; type: "create" | "get"; options: Record<string, unknown> } {
    return typeof value === "object" && value !== null
      && "channel" in value && value.channel === PASSKEY_PAGE_CHANNEL
      && "type" in value && (value.type === "create" || value.type === "get")
      && "options" in value && typeof value.options === "object" && value.options !== null;
  }

  function isWebPage(value: string): boolean {
    try {
      const url = new URL(value);
      return (url.protocol === "https:" || url.protocol === "http:") && url.hostname !== "";
    } catch {
      return false;
    }
  }

  function withoutFragment(value: string): string {
    const url = new URL(value);
    url.hash = "";
    return url.href;
  }

  function element<K extends keyof HTMLElementTagNameMap>(tag: K, className: string, text?: string): HTMLElementTagNameMap[K] {
    const value = document.createElement(tag);
    if (className !== "") value.className = className;
    if (text !== undefined) value.textContent = text;
    return value;
  }

  function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "Hasilan Pass could not complete the request.";
  }

  const MENU_CSS = `
    :host { all: initial; color-scheme: dark; }
    * { box-sizing: border-box; }
    .panel { overflow: hidden; border: 1px solid #414753; border-radius: 8px; color: #f8fafc; background: #14161d; box-shadow: 0 16px 40px rgb(0 0 0 / 28%); font-family: "Inter Variable", "SF Pro Display", Geist, Arial, sans-serif; }
    .header { display: flex; height: 40px; align-items: center; justify-content: space-between; padding: 0 11px 0 13px; border-bottom: 1px solid #20232d; }
    .brand { color: #8588ff; font-size: 11px; letter-spacing: .03em; }
    .close { width: 25px; height: 25px; border: 0; border-radius: 50%; color: #81919c; background: transparent; font-size: 18px; cursor: pointer; }
    .close:hover { color: #fff; background: #1d2029; }
    .list { max-height: 224px; overflow-y: auto; padding: 5px; }
    .credential { display: grid; width: 100%; grid-template-columns: 34px minmax(0, 1fr) auto; align-items: center; gap: 10px; border: 0; border-radius: 8px; padding: 8px; color: inherit; background: transparent; text-align: left; cursor: pointer; }
    .credential:hover, .credential:focus-visible, .credential.keyboard-selected { outline: 0; background: #1d2029; }
    .glyph { display: block; width: 34px; height: 34px; border: 0; border-radius: 0; color: transparent; background: transparent; object-fit: contain; }
    .copy { display: flex; min-width: 0; flex-direction: column; gap: 3px; }
    .copy strong, .copy small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .copy strong { color: #e2e8eb; font-size: 11px; }
    .copy small { color: #7e8f99; font-size: 9px; }
    .signal { color: #c8cbff; font-size: 8px; font-weight: 800; text-transform: uppercase; }
    .state { padding: 16px; }
    .state strong { color: #e2e8eb; font-size: 11px; }
    .state p { margin: 5px 0 0; color: #81919b; font-size: 9px; line-height: 1.5; }
  `;
})();

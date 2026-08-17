import { schedule } from "@ember/runloop";
import { apiInitializer } from "discourse/lib/api";
import getURL from "discourse/lib/get-url";

export default apiInitializer("0.11.1", (api) => {
  const PLUGIN_DISPLAY_NAME = "Discourse-Account-Security-Plugin";
  const GENERATED_FILTER = `plugin:${PLUGIN_DISPLAY_NAME}`;
  const FIXED_SETTINGS_URL = getURL(
    "/admin/site_settings/category/all_results?filter=account_security"
  );
  const SETTINGS_BUTTON_SELECTOR =
    `[data-plugin-setting-button="${PLUGIN_DISPLAY_NAME}"]`;

  let observer = null;
  let clickHandlerInstalled = false;
  let redirecting = false;

  function parsedUrl(value) {
    if (!value) {
      return null;
    }

    try {
      return new URL(value, window.location.origin);
    } catch {
      return null;
    }
  }

  function isGeneratedSettingsUrl(value) {
    const parsed = parsedUrl(value);
    return (
      parsed?.pathname?.includes("/admin/site_settings/") &&
      parsed.searchParams.get("filter") === GENERATED_FILTER
    );
  }

  function redirectGeneratedFilter(value) {
    if (redirecting || !isGeneratedSettingsUrl(value)) {
      return false;
    }

    redirecting = true;
    window.location.replace(FIXED_SETTINGS_URL);
    return true;
  }

  function findPluginCards() {
    return Array.from(document.querySelectorAll("[data-plugin-name]")).concat(
      Array.from(
        document.querySelectorAll(
          ".admin-plugins-list .admin-plugin, .admin-plugin"
        )
      )
    );
  }

  function cardLooksLikeOurPlugin(card) {
    if (!card) {
      return false;
    }

    const dataName = card.getAttribute?.("data-plugin-name");
    if (
      dataName &&
      dataName.toLowerCase() === PLUGIN_DISPLAY_NAME.toLowerCase()
    ) {
      return true;
    }

    const text = (card.textContent || "").toLowerCase();
    if (text.includes(PLUGIN_DISPLAY_NAME.toLowerCase())) {
      return true;
    }

    return Boolean(
      card.querySelector?.(`a[href*="${PLUGIN_DISPLAY_NAME}"]`)
    );
  }

  function fixControl(control) {
    if (!control || control.dataset.accountSecuritySettingsFixed === "1") {
      return;
    }

    control.setAttribute?.("href", FIXED_SETTINGS_URL);
    control.dataset.accountSecuritySettingsFixed = "1";
  }

  function rewriteGeneratedFilterLinks() {
    document
      .querySelectorAll('a[href*="/admin/site_settings/"]')
      .forEach((anchor) => {
        if (isGeneratedSettingsUrl(anchor.getAttribute("href"))) {
          fixControl(anchor);
        }
      });
  }

  function rewriteExactSettingsButtons() {
    document
      .querySelectorAll(SETTINGS_BUTTON_SELECTOR)
      .forEach((control) => fixControl(control));
  }

  function rewriteSettingsLinksInCards() {
    findPluginCards().forEach((card) => {
      if (!cardLooksLikeOurPlugin(card)) {
        return;
      }

      card
        .querySelectorAll('a[href*="/admin/site_settings/"]')
        .forEach((anchor) => fixControl(anchor));
    });
  }

  function rewriteAll() {
    schedule("afterRender", () => {
      rewriteGeneratedFilterLinks();
      rewriteExactSettingsButtons();
      rewriteSettingsLinksInCards();
    });
  }

  function installClickInterceptOnce() {
    if (clickHandlerInstalled) {
      return;
    }

    clickHandlerInstalled = true;
    document.addEventListener(
      "click",
      (event) => {
        const target = event.target;
        if (!target) {
          return;
        }

        const anchor = target.closest?.("a[href]");
        if (anchor && isGeneratedSettingsUrl(anchor.getAttribute("href"))) {
          event.preventDefault();
          event.stopPropagation();
          window.location.assign(FIXED_SETTINGS_URL);
          return;
        }

        if (!window.location?.pathname?.includes("/admin/plugins")) {
          return;
        }

        const exactControl = target.closest?.(SETTINGS_BUTTON_SELECTOR);
        if (exactControl) {
          event.preventDefault();
          event.stopPropagation();
          window.location.assign(FIXED_SETTINGS_URL);
          return;
        }

        const genericPluginSettingControl = target.closest?.(
          "[data-plugin-setting-button]"
        );
        if (
          genericPluginSettingControl &&
          cardLooksLikeOurPlugin(
            genericPluginSettingControl.closest?.(
              "[data-plugin-name], .admin-plugin"
            )
          )
        ) {
          event.preventDefault();
          event.stopPropagation();
          window.location.assign(FIXED_SETTINGS_URL);
          return;
        }

        const control =
          target.closest?.(
            'a[href*="/admin/site_settings"], button, .btn, .d-button'
          ) || target;
        const card = control.closest?.("[data-plugin-name], .admin-plugin");
        if (!cardLooksLikeOurPlugin(card)) {
          return;
        }

        const label = `${control.getAttribute?.("aria-label") || ""} ${
          control.getAttribute?.("title") || ""
        } ${control.textContent || ""}`.toLowerCase();
        const href = control.getAttribute?.("href") || "";
        if (!label.includes("settings") && !href.includes("/admin/site_settings")) {
          return;
        }

        event.preventDefault();
        event.stopPropagation();
        window.location.assign(FIXED_SETTINGS_URL);
      },
      true
    );
  }

  function start() {
    rewriteAll();
    installClickInterceptOnce();

    observer?.disconnect();
    observer = new MutationObserver(() => rewriteAll());
    observer.observe(document.body, { childList: true, subtree: true });
  }

  function stop() {
    observer?.disconnect();
    observer = null;
  }

  api.onPageChange((url) => {
    if (redirectGeneratedFilter(url)) {
      return;
    }

    redirecting = false;
    if (url?.includes("/admin/plugins")) {
      start();
    } else {
      stop();
    }
  });

  if (!redirectGeneratedFilter(window.location?.href)) {
    if (window.location?.pathname?.includes("/admin/plugins")) {
      start();
    }
  }
});

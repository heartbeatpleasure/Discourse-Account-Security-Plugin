import User from "discourse/models/user";

function userLocales() {
  const effectiveLocale = User.current()?.effective_locale;
  const preferred = effectiveLocale ? effectiveLocale.replace(/_/g, "-") : null;
  const browserLanguages = globalThis.navigator?.languages;
  const values = [];

  if (preferred) {
    values.push(preferred);
  }
  if (Array.isArray(browserLanguages)) {
    values.push(...browserLanguages);
  } else if (globalThis.navigator?.language) {
    values.push(globalThis.navigator.language);
  }

  const unique = [...new Set(values.filter(Boolean))];
  return unique.length ? unique : undefined;
}

export function accountSecurityUserTimezone() {
  const configuredTimezone = User.current()?.user_option?.timezone;
  if (configuredTimezone && moment.tz.zone(configuredTimezone)) {
    return configuredTimezone;
  }

  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || moment.tz.guess();
  } catch {
    return moment.tz.guess();
  }
}

export function formatAccountSecurityDateTime(value) {
  if (!value) {
    return "—";
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  const timezone = accountSecurityUserTimezone();

  try {
    return new Intl.DateTimeFormat(userLocales(), {
      timeZone: timezone,
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(parsed);
  } catch {
    const fallback = moment(value);
    if (!fallback.isValid()) {
      return value;
    }
    return fallback.tz(timezone).format("D MMMM YYYY, HH:mm");
  }
}

export function formatAccountSecurityDateOnly(value, { month = "long" } = {}) {
  if (!value) {
    return "—";
  }

  const match = String(value).match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) {
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return value;
    }
    try {
      return new Intl.DateTimeFormat(userLocales(), {
        timeZone: accountSecurityUserTimezone(),
        year: "numeric",
        month,
        day: "numeric",
      }).format(parsed);
    } catch {
      return value;
    }
  }

  const [, year, monthNumber, day] = match;
  const parsed = new Date(
    Date.UTC(Number(year), Number(monthNumber) - 1, Number(day), 12, 0, 0)
  );

  try {
    return new Intl.DateTimeFormat(userLocales(), {
      timeZone: "UTC",
      year: "numeric",
      month,
      day: "numeric",
    }).format(parsed);
  } catch {
    const fallbackFormat = month === "long" ? "D MMMM YYYY" : "D MMM YYYY";
    return moment.utc(value, "YYYY-MM-DD", true).format(fallbackFormat);
  }
}

export function accountSecurityLocalInputToIso(value) {
  if (!value) {
    return null;
  }

  const timezone = accountSecurityUserTimezone();
  const parsed = moment.tz(value, "YYYY-MM-DDTHH:mm", timezone);
  return parsed.isValid() ? parsed.toISOString() : null;
}

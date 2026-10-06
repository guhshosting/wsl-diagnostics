# JSON schema version 1

> Release context: see [qualified platforms, runtime requirements and package scope](../RELEASE-QUALIFICATION.md).


One UTF-8 JSON object, newline terminated. Keys sorted lexicographically, stable
array ordering (registration identity order for distributions, file order for
configuration). No localized strings are parsed. Consumers must tolerate extra
keys and new finding codes; `schema_version` changes for incompatible changes.

Envelope: `schema_version` integer 1, `tool_version` string `1.0.0`, `mode` string,
`findings` array. Summary includes `summary`, `prerequisites`, `registrations`,
`distributions`, `configuration`. Other commands include their named section;
distributions also includes `registrations`. Findings cover acquired sections.

Observations always contain `state`, `value`, `source`, `detail`, `win32_error`.
`value` is null when not known, otherwise string, integer or boolean. The Win32
error is numeric (0 when not applicable); KnownFolder HRESULT is stored unsigned
in that field when lookup fails. Never interpret null as false or zero.

| State | Meaning |
| --- | --- |
| present / absent | Source/entity observed / absent in this source |
| enabled / disabled | Capability positively observed enabled/disabled |
| available / unavailable | Value obtained / not obtained |
| access_denied | Permission failure |
| unsupported | Input/API/path policy outside implementation support |
| not_applicable | Observation does not apply |
| unknown | Available evidence does not establish an answer |

Not every state must occur on each host. Negative virtualization observations are
unknown, not disabled. Absent registry values remain absent, not false. An empty
distribution array is not proof of zero if `registrations.state` is unavailable
or access_denied. With complete enumeration, `registrations.value` is a count.

Each distribution has `registration_id` string and observations `name`,
`generation`, `state`, `default`, `base_path`, `package_identity`. Generation is
integer 1 or 2 when recognized. Unknown numeric generations are retained with
unknown state. Package identity absence may mean an unpackaged/imported
distribution; it does not mean distribution absence.

Configuration contains `file` observation, `entries` array, `malformed` boolean,
`effective_settings_verified` (always false). Entries contain line, section, key,
value, raw, status, detail. Status: section, recognized, unknown, malformed,
duplicate. Comments/blank lines aren't entries. Raw lines are decoded text, not
original encoding bytes. A malformed encoding marks the file present and
malformed without trying to invent entries.

Findings contain code, severity (info/warning), message; path findings also have
line and observation. Findings are evidence descriptions, not automatic repair
recommendations. Exit status does not encode severity.

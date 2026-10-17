# Sources

These are the tools this skill calls. None of them is a hard dependency. `requires_tools` is empty so the skill still loads when a connector is absent. Say which source is missing and continue with the evidence already supplied.

| Tool | Arguments | Missing sentence |
| --- | --- | --- |
| `mcp__e8__e8_requirements` | `strategy`, `maturity_level` (1, 2, or 3) | Essential Eight requirements source missing (`mcp__e8__e8_requirements`) |
| `mcp__e8__essentials_chapter` | `chapter` (`enterprise-it`, `cloud`, or `ot`), optional `domain` | ASD Essentials chapter source missing (`mcp__e8__essentials_chapter`) |
| `mcp__e8__essentials_transition` | `strategy` | ASD Essentials transition source missing (`mcp__e8__essentials_transition`) |
| `mcp__ism__ism_get_control` | `control_id` | ISM source missing (`mcp__ism__ism_get_control`), or the control is missing |
| `evidence_import` | `path` | M365-Secure evidence import source missing (`evidence_import`) |

The eight `strategy` values are `patch_applications`, `patch_operating_systems`, `multi_factor_authentication`, `restrict_admin_privileges`, `application_control`, `restrict_office_macros`, `user_application_hardening`, and `regular_backups`.

Pass `available: false` in the renderer input when a call cannot be made. Do not invent a payload. A control id the ISM tool does not return is missing, even if the input also contains a statement string.

There is no NIST tool. If the user asks for a NIST mapping and no NIST payload was retrieved, the NIST mapping source is missing.

The Essential Eight and ASD Essentials connector is not part of this skill. This skill does not notify anyone and does not post the workbook.

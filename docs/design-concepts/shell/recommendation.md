# Shell concepts: owner selection

**Selected by the owner on 2026-10-13: C, Two-level workbench.** Keep a narrow, labelled work-area rail and show only the current area's pages. Hide the page list when a table needs more width. The current area stays selected; the breadcrumb and page title remain visible. The owner authorized the production cutover after reviewing these static concepts.

- **A, Focus rail:** compact work-area rail with a labelled flyout. It offers the most space when closed, but repeated flyout opening adds friction. Keyboard focus and explicit opening must replace hover-only navigation.
- **B, Top workbench:** work areas in a top bar, with grouped mega-menus. It frees horizontal space for tables, but an open menu covers or displaces evidence. The desktop specimen shows that cost.
- **C, Two-level workbench:** stable work-area rail plus contextual pages. It makes location and nearby work clearest, at the cost of a 284px expanded navigation footprint. The collapsed specimen retains the 76px work-area rail.

## What changes in the information architecture

At selection time, the old shell exposed 14 destinations under Fleet, Security and Administration. These concepts proposed five work areas; they did not add product pages or permissions.

| Work area | Proposed destinations                                 | Existing routes                                   |
| --------- | ----------------------------------------------------- | ------------------------------------------------- |
| Fleet     | Dashboard, Devices, Enrollment, Device groups         | /dashboard, /devices, /enrollment, /groups        |
| Security  | Advisories, Secrets, Audit log                        | /advisories, /secrets, /audit                     |
| Changes   | Profiles, Rollouts, Approvals                         | /profiles, /rollouts, /approvals                  |
| Admin     | Accounts, Authorization, Account groups, Integrations | /accounts, /authorization, /groups, /integrations |
| Settings  | Server settings, Device capabilities                  | /settings and its existing detail routes          |

Device groups and Account groups are proposed contextual entry labels for the existing Groups page, not new independent routes. Settings labels likewise describe sections of existing pages. A selected implementation must define their entry state without duplicating records. Approvals moves to Changes because it gates operator changes; Security keeps advisory evidence. Preserve the existing shared authorization filter for navigation and command-palette pages. Hide areas with no authorized destinations.

## Shared shell and container decisions

- Show four main work areas plus Settings, not every page at once. Show the current area's four pages; C offers two labelled cross-area links.
- Use a full-width, flat content surface with a 1600px maximum and 28–32px desktop gutters. Do not wrap tables in an additional padded card. Detail forms can retain narrower readable columns.
- Keep 24px desktop / 20px mobile titles, 14px controls, 12px metadata and compact table rows. Use bundled IBM Plex Sans, zero radius and semantic light/dark colours.
- Keep the decision above evidence. On mobile, turn each table row into a named record; retain observation time and next step. No fixed-width desktop table forces document overflow.
- Reserve command-palette and account controls in the header. Keep the current area, breadcrumb and page title when navigation collapses. The rail uses text labels as well as icons.
- Mobile uses a labelled Menu disclosure and one area at a time. The supplied navigation captures show that state. Production selection needs a closable modal drawer with focus containment, Escape, focus return and body-scroll handling; static disclosures do not prove those behaviours.
- The HTML includes navigation landmarks, a skip link, native links/disclosures, visible focus and aria-current. No hover-only access or motion is required. A selected production shell must preserve scoped permissions, command-palette keyboard handling and account-menu semantics.

## Open the mockups

Open [index.html](index.html) for all screenshot links. Each HTML specimen uses local CSS; the cache bundle includes the font and its notice. The HTML is static: buttons and route fragments show positions, not working console actions. Names, counts, times and outcomes are illustrative, not fleet evidence. Desktop screenshots are 1440×900; mobile page screenshots are 390px wide and full-length, with separate 390×844 navigation screenshots. Both light and dark are real browser renders.

## Required design review

- **Decision: pass (concept scope).** The specimen leads with the inventory decision and names the unknown update state. No action is sent.
- **Evidence: pass (concept scope).** All specimen data is labelled illustrative. No synthetic health or execution success is presented as observed fleet evidence.
- **Restraint: pass (concept scope).** Flat rows, one decision band, task groups, no charts, scorecards or generic card grid.
- **Safety: not applicable to static actions.** These drawings cannot mutate devices. Production confirmation, consent, approval and ambiguous-outcome handling remain untouched.
- **Craft: needs owner decision.** Compare A/B/C in both themes and widths. Native focus and landmarks are present; these screenshots do not qualify production keyboard, screen-reader or drawer behaviour.
- **Editing: pass (selection record).** The owner selected C and requested the persistent page column, a proper collapse icon/shortcut, consistent mobile lists and a wide-table container. Production Groups remains one page in Admin, with a Fleet Related work link; the contextual split labels in these original drawings do not create new routes.

The collapsed-logo defect landed independently before the selected-shell cutover.

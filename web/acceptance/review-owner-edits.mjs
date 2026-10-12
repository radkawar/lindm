// Owner edit-pass acceptance (docs/design.md "Required design review"): each
// imported owner task's observable acceptance criterion, checked against the
// seeded demo fleet through the real console. A pass establishes that criterion
// only; it is not owner approval of the edited screen.
import { ownerEdits } from "./owner-edits/index.mjs";

function slug(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

// Runs on one signed-in page, light desktop, before task walkthroughs add state.
export async function reviewOwnerEdits({ page, config, visit, settle, screenshot }) {
  const results = [];
  for (const edit of ownerEdits) {
    const { task } = edit;
    const findings = [];
    const screenshots = [];
    const require = (value, message) => {
      if (!value) findings.push(message);
    };
    // A check may capture its own page, e.g. a separate signed-out context.
    const capture = async (name, target = page) => {
      await settle(target);
      screenshots.push(
        await screenshot(target, `owner-edit-${slug(task.name)}-${slug(name)}.png`, true),
      );
    };
    let step = "start";
    try {
      await edit.check({
        page,
        config,
        demo: config.demo,
        visit: (url) => visit(page, url),
        settle: () => settle(page),
        require,
        capture,
        step: (name) => {
          step = name;
        },
      });
    } catch (error) {
      // Only the first line: Playwright call logs can echo filled form values.
      findings.push(
        `check did not complete at step "${step}": ${String(error?.message ?? error).split("\n")[0]}`,
      );
      screenshots.push(
        await screenshot(page, `owner-edit-${slug(task.name)}-failure.png`, true).catch(() => ""),
      );
    }
    results.push({ ...task, passed: findings.length === 0, findings, screenshots });
  }
  return results;
}

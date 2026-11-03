/**
 * The API's password rules (core/security.py), checked before the request so the person
 * sees every missing piece at once. The API stays the authority.
 */
export const MIN_PASSWORD = 10;

export function passwordIssues(password: string): string[] {
  const issues: string[] = [];
  if (password.length < MIN_PASSWORD) issues.push(`at least ${MIN_PASSWORD} characters`);
  if (password.toLowerCase() === password || password.toUpperCase() === password) issues.push("upper and lower case letters");
  if (!/\d/.test(password)) issues.push("a digit");
  return issues;
}

/** "Use at least 10 characters, upper and lower case letters and a digit." or null. */
export function passwordMessage(password: string): string | null {
  const issues = passwordIssues(password);
  if (!issues.length) return null;
  const list = issues.length > 1 ? `${issues.slice(0, -1).join(", ")} and ${issues[issues.length - 1]}` : issues[0];
  return `Use ${list}.`;
}

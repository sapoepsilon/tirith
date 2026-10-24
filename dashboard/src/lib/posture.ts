export function gradeFor(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function gradeColor(grade: string): string {
  switch (grade) {
    case "A":
      return "var(--color-ok)";
    case "B":
      return "var(--color-accent)";
    case "C":
      return "var(--color-sev-medium)";
    case "D":
      return "var(--color-sev-high)";
    default:
      return "var(--color-sev-critical)";
  }
}
